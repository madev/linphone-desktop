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

#include "LoginPage.hpp"
#include <QTimer>

#include "core/App.hpp"

#include "model/account/AccountManager.hpp"
#include "model/auth/InviaPbxAuthModel.hpp"

DEFINE_ABSTRACT_OBJECT(LoginPage)

LoginPage::LoginPage(QObject *parent) : QObject(parent) {
	mustBeInMainThread(getClassName());
}

LoginPage::~LoginPage() {
	mustBeInMainThread("~" + getClassName());
}

linphone::RegistrationState LoginPage::getRegistrationState() const {
	// View thread
	return mRegistrationState;
}

void LoginPage::setRegistrationState(linphone::RegistrationState status) {
	// Should be view thread only because of object updates.
	mustBeInMainThread(log().arg(Q_FUNC_INFO));
	if (mRegistrationState != status) {
		mRegistrationState = status;
		emit registrationStateChanged();
	}
}

QString LoginPage::getErrorMessage() const {
	return mErrorMessage;
}

void LoginPage::setErrorMessage(const QString &error) {
	if (mErrorMessage != error) {
		mErrorMessage = error;
		emit errorMessageChanged(error);
	}
}

bool LoginPage::getInviaPbxLoading() const {
	return mInviaPbxLoading;
}

void LoginPage::setInviaPbxLoading(bool loading) {
	if (mInviaPbxLoading != loading) {
		mInviaPbxLoading = loading;
		emit inviaPbxLoadingChanged();
	}
}

void LoginPage::loginInviaPbx() {
	mustBeInMainThread(log().arg(Q_FUNC_INFO));
	setErrorMessage("");
	setInviaPbxLoading(true);

	auto authModel = new InviaPbxAuthModel(this);

	connect(authModel, &InviaPbxAuthModel::loginFailed, this, [this, authModel](const QString &error) {
		setErrorMessage(error);
		setInviaPbxLoading(false);
		authModel->deleteLater();
	});

	connect(authModel, &InviaPbxAuthModel::credentialsFetched, this,
	        [this, authModel](const QString &sipUsername, const QString &sipSecret, const QString &sipDomain,
	                          const QString &sipServer) {
		        authModel->deleteLater();

		        auto registrarUri = QStringLiteral("sip:%1:5060;transport=udp").arg(sipServer);

		        App::postModelAsync([=]() {
			        AccountManager *accountManager = new AccountManager();
			        connect(accountManager, &AccountManager::registrationStateChanged, this,
			                [accountManager, this](linphone::RegistrationState state, linphone::Reason reason,
			                                       QString message) mutable {
				                setRegistrationState(state);
				                mBadIds = reason == linphone::Reason::Forbidden;
				                emit reasonChanged();
				                switch (state) {
					                case linphone::RegistrationState::Failed: {
						                if (message.isEmpty())
							                setErrorMessage(tr("default_account_connection_state_error_toast"));
						                else setErrorMessage(message);
						                setInviaPbxLoading(false);
						                if (accountManager) {
							                accountManager->deleteLater();
							                accountManager = nullptr;
						                }
						                break;
					                }
					                case linphone::RegistrationState::Ok: {
						                setInviaPbxLoading(false);
						                if (accountManager) {
							                accountManager->deleteLater();
							                accountManager = nullptr;
						                }
						                break;
					                }
					                case linphone::RegistrationState::Cleared: {
						                setInviaPbxLoading(false);
						                if (accountManager) {
							                accountManager->deleteLater();
							                accountManager = nullptr;
						                }
						                break;
					                }
					                case linphone::RegistrationState::None:
					                case linphone::RegistrationState::Progress:
					                case linphone::RegistrationState::Refreshing:
						                break;
				                }
			                });

			        QString error;
			        if (!accountManager->login(sipUsername, sipSecret, sipUsername, sipDomain,
			                                   linphone::TransportType::Udp, &error, registrarUri)) {
				        setErrorMessage(error);
				        setInviaPbxLoading(false);
				        emit accountManager->registrationStateChanged(linphone::RegistrationState::None,
				                                                      linphone::Reason::None);
			        }
		        });
	        });

	authModel->startLogin();
}

void LoginPage::login(const QString &username,
                      const QString &password,
                      QString displayName,
                      QString domain,
                      LinphoneEnums::TransportType transportType,
                      QString registrarUri,
                      QString outboundProxyAddress,
                      QString connectionId) {
	setErrorMessage("");
	App::postModelAsync([=]() {
		// Create on Model thread.
		AccountManager *accountManager = new AccountManager();
		connect(accountManager, &AccountManager::registrationStateChanged, this,
		        [accountManager, this](linphone::RegistrationState state, linphone::Reason reason,
		                               QString message) mutable {
			        // View thread
			        setRegistrationState(state);
			        mBadIds = reason == linphone::Reason::Forbidden;
			        emit reasonChanged();
			        switch (state) {
				        case linphone::RegistrationState::Failed: {
					        if (message.isEmpty())
						        //: Erreur durant la connexion, veuillez vérifier vos paramètres
						        setErrorMessage(tr("default_account_connection_state_error_toast"));
					        else setErrorMessage(message);
					        if (accountManager) {
						        accountManager->deleteLater();
						        accountManager = nullptr;
					        }
					        break;
				        }
				        case linphone::RegistrationState::Ok: {
					        // setErrorMessage("");
					        if (accountManager) {
						        accountManager->deleteLater();
						        accountManager = nullptr;
					        }
					        break;
				        }
				        case linphone::RegistrationState::Cleared: {
					        if (accountManager) {
						        accountManager->deleteLater();
						        accountManager = nullptr;
					        }
					        break;
				        }
				        case linphone::RegistrationState::None:
				        case linphone::RegistrationState::Progress:
				        case linphone::RegistrationState::Refreshing:
					        break;
			        }
		        });

		QString error;
		if (!accountManager->login(username, password, displayName, domain, LinphoneEnums::toLinphone(transportType),
		                           &error, registrarUri, outboundProxyAddress, connectionId)) {
			setErrorMessage(error);
			emit accountManager->registrationStateChanged(linphone::RegistrationState::None, linphone::Reason::None);
		}
	});
}
