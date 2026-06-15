/*
 * Copyright (c) 2010-2024 Belledonne Communications SARL.
 *
 * This file is part of linphone-desktop
 * (see https://www.linphone.org).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "InviaPbxAuthModel.hpp"

#include <QDesktopServices>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QUrlQuery>
#include <QtNetworkAuth>

#include "model/core/CoreModel.hpp"
#include "tool/Utils.hpp"

DEFINE_ABSTRACT_OBJECT(InviaPbxAuthModel)

static constexpr char DefaultAuthority[] = "https://login.microsoftonline.com/invia.de";
static constexpr char DefaultClientId[] = "927889d2-e49b-49ac-a602-800b294b5276";
static constexpr char DefaultScope[] = "api://ad7d29f8-387f-4b04-b177-85888abf52a7/user_impersonation";
static constexpr char DefaultApiBaseUrl[] = "https://api.it.invia.eu/usermanagement/linuxbox";
static constexpr char ConfigSection[] = "app";
static constexpr char RefreshTokenKey[] = "invia_oauth_refresh_token";

InviaPbxAuthModel::InviaPbxAuthModel(QObject *parent) : QObject(parent) {
	mNetworkManager = new QNetworkAccessManager(this);
	mTimeout.setSingleShot(true);
	mTimeout.setInterval(1000 * 60 * 2); // 2 minutes
}

InviaPbxAuthModel::~InviaPbxAuthModel() {
}

void InviaPbxAuthModel::startLogin() {
	auto config = CoreModel::getInstance()->getCore()->getConfig();

	auto authority = QString::fromStdString(config->getString("app", "invia_oauth_authority", DefaultAuthority));
	auto clientId = QString::fromStdString(config->getString("app", "invia_oauth_client_id", DefaultClientId));
	auto scope = QString::fromStdString(config->getString("app", "invia_oauth_scope", DefaultScope));
	mApiBaseUrl = QString::fromStdString(config->getString("app", "invia_api_base_url", DefaultApiBaseUrl));
	auto redirectPort = config->getInt("app", "invia_oauth_redirect_port", 0);

	lInfo() << log().arg("Starting Invia PBX OAuth2 login");
	lInfo() << log().arg("Authority: ") << authority;
	lInfo() << log().arg("Client ID: ") << clientId;

	auto replyHandler = new QOAuthHttpServerReplyHandler(redirectPort, this);
	if (!replyHandler->isListening()) {
		lWarning() << log().arg("OAuthHttpServerReplyHandler is not listening on port") << redirectPort;
		emit loginFailed(tr("Failed to start local OAuth server"));
		return;
	}

	mOAuth.setReplyHandler(replyHandler);
	mOAuth.setAuthorizationUrl(QUrl(authority + "/oauth2/v2.0/authorize"));
#if QT_VERSION >= QT_VERSION_CHECK(6, 9, 0)
	mOAuth.setTokenUrl(QUrl(authority + "/oauth2/v2.0/token"));
#else
	mOAuth.setAccessTokenUrl(QUrl(authority + "/oauth2/v2.0/token"));
#endif
	mOAuth.setClientIdentifier(clientId);
	mOAuth.setNetworkAccessManager(mNetworkManager);

#if QT_VERSION >= QT_VERSION_CHECK(6, 9, 0)
	QSet<QByteArray> scopeTokens;
	scopeTokens.insert(scope.toUtf8());
	scopeTokens.insert("offline_access");
	mOAuth.setRequestedScopeTokens(scopeTokens);
#else
	mOAuth.setScope(scope + " offline_access");
#endif

	connect(&mTimeout, &QTimer::timeout, this, [this]() {
		lWarning() << log().arg("Timeout reached for Invia PBX OAuth2 login");
		if (mFinished) return;
		mFinished = true;
		auto handler = dynamic_cast<QOAuthHttpServerReplyHandler *>(mOAuth.replyHandler());
		if (handler) handler->close();
		emit loginFailed(tr("Authentication timed out"));
	});

	// statusChanged — log all transitions, only act on Granted
	connect(&mOAuth, &QOAuth2AuthorizationCodeFlow::statusChanged, this, [this](QAbstractOAuth::Status status) {
		lInfo() << log().arg("OAuth2 statusChanged:") << static_cast<int>(status);
		if (status == QAbstractOAuth::Status::Granted && !mGranted) {
			mGranted = true;
			mTimeout.stop();
			onOAuthGranted();
		}
	});

	connect(&mOAuth, &QOAuth2AuthorizationCodeFlow::requestFailed, this, [this](QAbstractOAuth::Error error) {
		lWarning() << log().arg("OAuth2 request failed, error code:") << static_cast<int>(error);
		if (mFinished) return;
		mFinished = true;
		mTimeout.stop();
		const QMetaObject metaObject = QAbstractOAuth::staticMetaObject;
		int index = metaObject.indexOfEnumerator("Error");
		QMetaEnum metaEnum = metaObject.enumerator(index);
		QString errorName = metaEnum.valueToKey(static_cast<int>(error));
		emit loginFailed(tr("Authentication failed: %1").arg(errorName));
	});

	connect(&mOAuth, &QOAuth2AuthorizationCodeFlow::authorizeWithBrowser, this, [this](const QUrl &url) {
		lInfo() << log().arg("Opening browser for Invia PBX authentication");
		lInfo() << log().arg("Auth URL:") << url.toString();
		emit statusMessage(tr("Opening browser for authentication..."));
		QDesktopServices::openUrl(url);
	});

	// Capture token exchange network replies for debugging
	connect(&mOAuth, &QOAuth2AuthorizationCodeFlow::finished, this, [this](QNetworkReply *reply) {
		lInfo() << log().arg("OAuth2 finished signal, reply URL:") << reply->url().toString();
		lInfo() << log().arg("OAuth2 finished signal, HTTP status:")
		        << reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
		connect(reply, &QNetworkReply::errorOccurred, this, [this, reply](QNetworkReply::NetworkError error) {
			lWarning() << log().arg("Token exchange network error:") << static_cast<int>(error) << reply->errorString();
			auto body = reply->readAll();
			lWarning() << log().arg("Token exchange error response body:") << body;
		});
	});

#if QT_VERSION >= QT_VERSION_CHECK(6, 9, 0)
	connect(&mOAuth, &QOAuth2AuthorizationCodeFlow::granted, this, [this]() {
		lInfo() << log().arg("OAuth2 granted() signal received");
		if (!mGranted) {
			mGranted = true;
			mTimeout.stop();
			onOAuthGranted();
		}
	});
#endif

	// Log callback and tokens from reply handler
	connect(replyHandler, &QOAuthHttpServerReplyHandler::callbackReceived, this, [this](const QVariantMap &params) {
		lInfo() << log().arg("OAuth callback received from browser, params:");
		for (auto it = params.cbegin(); it != params.cend(); ++it) {
			lInfo() << "  " << it.key() << " = " << it.value().toString().left(30) << "...";
		}
	});

	connect(replyHandler, &QOAuthHttpServerReplyHandler::tokensReceived, this, [this](const QVariantMap &tokens) {
		lInfo() << log().arg("Tokens received from token exchange, keys:");
		for (auto it = tokens.cbegin(); it != tokens.cend(); ++it) {
			lInfo() << "  " << it.key() << " = " << it.value().toString().left(20) << "...";
		}
	});

	lInfo() << log().arg("Reply handler listening on port:") << replyHandler->port();
	lInfo() << log().arg("Authorization URL:") << mOAuth.authorizationUrl().toString();
#if QT_VERSION >= QT_VERSION_CHECK(6, 9, 0)
	lInfo() << log().arg("Token URL:") << mOAuth.tokenUrl().toString();
#else
	lInfo() << log().arg("Token URL:") << mOAuth.accessTokenUrl().toString();
#endif

	mTimeout.start();
	emit statusMessage(tr("Starting authentication..."));
	mOAuth.grant();
}

void InviaPbxAuthModel::onOAuthGranted() {
	mAccessToken = mOAuth.token();
	auto refreshToken = mOAuth.refreshToken();
	if (!refreshToken.isEmpty()) {
		persistRefreshToken(refreshToken);
		lInfo() << log().arg("Refresh token persisted for future silent firewall refresh");
	} else {
		lWarning() << log().arg(
		    "No refresh token returned from OAuth provider; startup firewall refresh will be skipped");
	}
	lInfo() << log().arg("OAuth2 token obtained, fetching SIP credentials");
	emit statusMessage(tr("Fetching SIP credentials..."));
	fetchCredentials();
}

void InviaPbxAuthModel::fetchCredentials() {
	QNetworkRequest request(QUrl(mApiBaseUrl + "/credential"));
	request.setRawHeader("Authorization", ("Bearer " + mAccessToken).toUtf8());
	request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

	auto reply = mNetworkManager->get(request);
	connect(reply, &QNetworkReply::finished, this, [this, reply]() {
		reply->deleteLater();

		if (reply->error() != QNetworkReply::NoError) {
			int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
			lWarning() << log().arg("Failed to fetch SIP credentials, HTTP status:") << httpStatus
			           << reply->errorString();
			emit loginFailed(tr("Failed to fetch SIP credentials (HTTP %1)").arg(httpStatus));
			return;
		}

		auto responseData = reply->readAll();
		lInfo() << log().arg("Credentials response received");

		auto doc = QJsonDocument::fromJson(responseData);
		if (doc.isNull() || !doc.isObject()) {
			lWarning() << log().arg("Invalid JSON response for credentials");
			emit loginFailed(tr("Invalid credentials response from server"));
			return;
		}

		auto obj = doc.object();

		// Log all keys for debugging
		lInfo() << log().arg("Credentials JSON keys:");
		for (auto it = obj.begin(); it != obj.end(); ++it) {
			lInfo() << "  " << it.key() << " = " << it.value().toString().left(30);
		}

		// Try both PascalCase (C# model) and camelCase (possible JSON serialization)
		auto sipUsername = obj.contains("SipUsername") ? obj["SipUsername"].toString() : obj["sipUsername"].toString();
		auto sipSecret = obj.contains("SipSecret") ? obj["SipSecret"].toString() : obj["sipSecret"].toString();
		auto sipDomain = obj.contains("SipDomain") ? obj["SipDomain"].toString() : obj["sipDomain"].toString();
		auto sipServer = obj.contains("SipServer") ? obj["SipServer"].toString() : obj["sipServer"].toString();

		if (sipUsername.isEmpty() || sipSecret.isEmpty() || sipServer.isEmpty()) {
			lWarning() << log().arg("Incomplete SIP credentials received. username=") << sipUsername
			           << " secret=" << (sipSecret.isEmpty() ? "EMPTY" : "SET") << " server=" << sipServer;
			emit loginFailed(tr("Incomplete SIP credentials received from server"));
			return;
		}

		if (sipDomain.isEmpty()) {
			sipDomain = "invia";
		}

		lInfo() << log().arg("SIP credentials fetched successfully for user:") << sipUsername;

		// Create firewall rule (non-blocking)
		createFirewallRule();

		emit credentialsFetched(sipUsername, sipSecret, sipDomain, sipServer);
	});
}

void InviaPbxAuthModel::createFirewallRule() {
	QNetworkRequest request(QUrl(mApiBaseUrl + "/firewall-allow-rules/self"));
	request.setRawHeader("Authorization", ("Bearer " + mAccessToken).toUtf8());
	request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

	auto reply = mNetworkManager->post(request, QByteArray());
	connect(reply, &QNetworkReply::finished, this, [this, reply]() {
		reply->deleteLater();
		if (reply->error() != QNetworkReply::NoError) {
			int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
			lWarning() << log().arg("Failed to create firewall allow rule, HTTP status:") << httpStatus
			           << reply->errorString();
		} else {
			lInfo() << log().arg("Firewall allow rule created successfully");
		}
		emit finished();
	});
}

void InviaPbxAuthModel::persistRefreshToken(const QString &refreshToken) {
	auto config = CoreModel::getInstance()->getCore()->getConfig();
	config->setString(ConfigSection, RefreshTokenKey, refreshToken.toStdString());
	config->sync();
}

QString InviaPbxAuthModel::loadRefreshToken() const {
	auto config = CoreModel::getInstance()->getCore()->getConfig();
	return QString::fromStdString(config->getString(ConfigSection, RefreshTokenKey, ""));
}

void InviaPbxAuthModel::refreshAndAllowFirewall() {
	auto refreshToken = loadRefreshToken();
	if (refreshToken.isEmpty()) {
		lInfo() << log().arg("No persisted Invia refresh token; skipping startup firewall refresh");
		emit finished();
		return;
	}

	auto config = CoreModel::getInstance()->getCore()->getConfig();
	auto authority = QString::fromStdString(config->getString("app", "invia_oauth_authority", DefaultAuthority));
	auto clientId = QString::fromStdString(config->getString("app", "invia_oauth_client_id", DefaultClientId));
	auto scope = QString::fromStdString(config->getString("app", "invia_oauth_scope", DefaultScope));
	mApiBaseUrl = QString::fromStdString(config->getString("app", "invia_api_base_url", DefaultApiBaseUrl));

	lInfo() << log().arg("Refreshing Invia OAuth access token for startup firewall allow rule");

	QNetworkRequest tokenRequest(QUrl(authority + "/oauth2/v2.0/token"));
	tokenRequest.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

	QUrlQuery body;
	body.addQueryItem("grant_type", "refresh_token");
	body.addQueryItem("client_id", clientId);
	body.addQueryItem("refresh_token", refreshToken);
	body.addQueryItem("scope", scope + " offline_access");

	auto reply = mNetworkManager->post(tokenRequest, body.toString(QUrl::FullyEncoded).toUtf8());
	connect(reply, &QNetworkReply::finished, this, [this, reply]() {
		reply->deleteLater();

		if (reply->error() != QNetworkReply::NoError) {
			int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
			auto body = reply->readAll();
			lWarning() << log().arg("Token refresh failed, HTTP status:") << httpStatus << reply->errorString();
			lWarning() << log().arg("Token refresh error body:") << body;
			// Refresh token rejected by IdP (revoked, rotated out, or expired beyond grace).
			// Fall back to interactive browser login to re-bootstrap the token. Network errors
			// (httpStatus == 0) must NOT trigger a browser popup.
			if (httpStatus == 400 || httpStatus == 401) {
				lInfo() << log().arg("Refresh token rejected by IdP, falling back to interactive login");
				startLogin();
				return;
			}
			emit finished();
			return;
		}

		auto doc = QJsonDocument::fromJson(reply->readAll());
		if (doc.isNull() || !doc.isObject()) {
			lWarning() << log().arg("Token refresh returned invalid JSON");
			emit finished();
			return;
		}

		auto obj = doc.object();
		auto accessToken = obj["access_token"].toString();
		auto newRefreshToken = obj["refresh_token"].toString();

		if (accessToken.isEmpty()) {
			lWarning() << log().arg("Token refresh response missing access_token");
			emit finished();
			return;
		}

		mAccessToken = accessToken;
		// Azure AD rotates refresh tokens — persist the new one if returned.
		if (!newRefreshToken.isEmpty()) {
			persistRefreshToken(newRefreshToken);
		}

		lInfo() << log().arg("Access token refreshed, calling firewall allow rule API");
		createFirewallRule();
	});
}
