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

#ifndef INVIA_PBX_AUTH_MODEL_H_
#define INVIA_PBX_AUTH_MODEL_H_

#include "tool/AbstractObject.hpp"
#include <QNetworkAccessManager>
#include <QOAuth2AuthorizationCodeFlow>
#include <QTimer>

class InviaPbxAuthModel : public QObject, public AbstractObject {
	Q_OBJECT

public:
	explicit InviaPbxAuthModel(QObject *parent = nullptr);
	~InviaPbxAuthModel();

	void startLogin();

signals:
	void credentialsFetched(const QString &sipUsername,
	                        const QString &sipSecret,
	                        const QString &sipDomain,
	                        const QString &sipServer);
	void loginFailed(const QString &errorMessage);
	void statusMessage(const QString &message);

private:
	void onOAuthGranted();
	void fetchCredentials();
	void createFirewallRule();

	QOAuth2AuthorizationCodeFlow mOAuth;
	QNetworkAccessManager *mNetworkManager = nullptr;
	QString mAccessToken;
	QTimer mTimeout;
	bool mGranted = false;
	bool mFinished = false;

	QString mApiBaseUrl;

	DECLARE_ABSTRACT_OBJECT
};

#endif
