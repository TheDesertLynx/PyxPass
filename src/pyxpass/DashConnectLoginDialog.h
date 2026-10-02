/*
 *  PyxPass — Dash-backed password manager (KeePassXC fork)
 *
 *  DashConnectLoginDialog: Milestone 10b. App-side DashConnect login UI.
 *  Calls sidecar dashconnectInit -> shows the dash-key: URI as a QR code +
 *  copyable text, polls dashconnectPoll until the wallet responds (ready) or
 *  the request expires, then prompts for the master password and calls
 *  dashconnectComplete. Does NOT unlock the vault — the caller does that with
 *  the entered password via the normal unlock() flow.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 */

#ifndef KEEPASSXC_DASHCONNECTLOGINDIALOG_H
#define KEEPASSXC_DASHCONNECTLOGINDIALOG_H

#include <QDialog>
#include <QPointer>

class QLabel;
class QLineEdit;
class QPushButton;
class QTimer;
class SquareSvgWidget;

namespace PyxPass
{
    class Client;

    /**
     * DashConnect login dialog. Non-blocking: it opens, shows the QR, and
     * emits ready(QString identityId, QString password) once the wallet
     * responds and the user confirms the master password. The caller then
     * completes the login / unlocks the vault.
     */
    class DashConnectLoginDialog : public QDialog
    {
        Q_OBJECT

    public:
        explicit DashConnectLoginDialog(const QString& label = QStringLiteral("Login to PyxPass"),
                                        QWidget* parent = nullptr);
        ~DashConnectLoginDialog() override;

        QString connectionId() const { return m_connectionId; }
        QString uri() const { return m_uri; }

    signals:
        /** identityId (from the wallet), password (user-confirmed) */
        void ready(const QString& identityId, const QString& password);

    private slots:
        void poll();
        void onReady();
        void confirmIdentity();
        void copyUri();
        void cancel();

    private:
        void startInit(const QString& label);
        void setStatus(const QString& text, bool error = false);
        void showConfirmation(const QString& identityId);
        void showPasswordPrompt();

        PyxPass::Client* m_client = nullptr;
        QString m_connectionId;
        QString m_uri;
        QString m_identityId;

        QLabel* m_qrLabel = nullptr;
        SquareSvgWidget* m_qrWidget = nullptr;
        QLineEdit* m_uriEdit = nullptr;
        QLabel* m_status = nullptr;
        QPushButton* m_copyButton = nullptr;
        QPushButton* m_doneButton = nullptr;
        QTimer* m_timer = nullptr;

        // Confirmation panel (M11a)
        QLabel* m_confirmLabel = nullptr;
        QLabel* m_confirmWarnings = nullptr;
        QLineEdit* m_confirmEdit = nullptr;
        QPushButton* m_confirmButton = nullptr;

        int m_polls = 0;
        bool m_ready = false;
        bool m_confirmed = false;
        QString m_expectedConfirm;
    };
} // namespace PyxPass

#endif // KEEPASSXC_DASHCONNECTLOGINDIALOG_H
