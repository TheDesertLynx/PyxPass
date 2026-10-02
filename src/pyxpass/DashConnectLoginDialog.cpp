/*
 *  PyxPass — Dash-backed password manager (KeePassXC fork)
 *
 *  DashConnectLoginDialog: Milestone 10b. See header for details.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 */

#include "DashConnectLoginDialog.h"

#include "PyxPassClient.h"

#include "gui/SquareSvgWidget.h"
#include "qrcode/QrCode.h"

#include <QApplication>
#include <QBuffer>
#include <QClipboard>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>
#include <QUrl>
#include <QUrlQuery>

namespace PyxPass
{
    // Poll every 3 s; give up after 5 minutes (matches request expiry).
    static const int POLL_INTERVAL_MS = 3000;
    static const int MAX_POLLS = 100;

    DashConnectLoginDialog::DashConnectLoginDialog(const QString& label, QWidget* parent)
        : QDialog(parent)
        , m_client(new Client())
        , m_qrLabel(new QLabel(tr("Scan this code with your Dash wallet, then confirm the login.")))
        , m_qrWidget(new SquareSvgWidget(this))
        , m_uriEdit(new QLineEdit())
        , m_status(new QLabel())
        , m_copyButton(new QPushButton(tr("Copy URI")))
        , m_doneButton(new QPushButton(tr("Done")))
        , m_timer(new QTimer(this))
    {
        setWindowTitle(tr("DashConnect Login"));
        setModal(false);

        auto* root = new QVBoxLayout(this);
        root->addWidget(m_qrLabel);

        auto* qrWrap = new QHBoxLayout();
        qrWrap->addStretch(1);
        qrWrap->addWidget(m_qrWidget);
        qrWrap->addStretch(1);
        root->addLayout(qrWrap);

        m_uriEdit->setReadOnly(true);
        root->addWidget(m_uriEdit);

        auto* btnRow = new QHBoxLayout();
        btnRow->addWidget(m_copyButton);
        btnRow->addStretch(1);
        btnRow->addWidget(m_doneButton);
        root->addLayout(btnRow);

        m_status->setWordWrap(true);
        root->addWidget(m_status);

        m_doneButton->setEnabled(false);

        connect(m_copyButton, &QPushButton::clicked, this, &DashConnectLoginDialog::copyUri);
        connect(m_doneButton, &QPushButton::clicked, this, &DashConnectLoginDialog::onReady);
        connect(m_timer, &QTimer::timeout, this, &DashConnectLoginDialog::poll);
        connect(this, &QDialog::rejected, this, &DashConnectLoginDialog::cancel);

        m_timer->setInterval(POLL_INTERVAL_MS);
        startInit(label);
    }

    DashConnectLoginDialog::~DashConnectLoginDialog()
    {
        if (m_timer->isActive()) {
            m_timer->stop();
        }
        delete m_client;
    }

    void DashConnectLoginDialog::startInit(const QString& label)
    {
        QString err;
        if (!m_client->dashconnectInit(QStringLiteral("self"), label, &m_connectionId, &m_uri, &err)) {
            setStatus(tr("Could not start DashConnect: %1").arg(err), true);
            return;
        }

        m_uriEdit->setText(m_uri);
        const QrCode qrc(m_uri);
        if (qrc.isValid()) {
            QBuffer buffer;
            qrc.writeSvg(&buffer, logicalDpiX());
            m_qrWidget->load(buffer.data());
        } else {
            m_qrLabel->setText(tr("Could not render the login QR code. Copy the URI below instead."));
        }

        setStatus(tr("Waiting for your Dash wallet to respond\u2026"));
        m_timer->start();
    }

    void DashConnectLoginDialog::poll()
    {
        if (m_ready) {
            return;
        }
        if (++m_polls > MAX_POLLS) {
            setStatus(tr("Request expired. Close this dialog and try again."), true);
            m_timer->stop();
            return;
        }

        QString status;
        QString identityId;
        QString err;
        if (!m_client->dashconnectPoll(m_connectionId, &status, &identityId, &err)) {
            setStatus(tr("Poll error: %1").arg(err), true);
            m_timer->stop();
            return;
        }

        if (status == QStringLiteral("ready")) {
            setStatus(tr("Wallet confirmed. Enter your master password to finish."));
            m_ready = true;
            m_timer->stop();
            m_doneButton->setEnabled(true);
            m_status->setProperty("identityId", identityId);
        } else if (status == QStringLiteral("expired")) {
            setStatus(tr("Request expired. Close this dialog and try again."), true);
            m_timer->stop();
        }
        // "pending": keep polling.
    }

    void DashConnectLoginDialog::onReady()
    {
        bool ok = false;
        const QString password = QInputDialog::getText(this,
                                                       tr("PyxPass Unlock"),
                                                       tr("Master password:"),
                                                       QLineEdit::Password,
                                                       QString(),
                                                       &ok);
        if (!ok || password.isEmpty()) {
            return;
        }

        QString identityId;
        QString err;
        if (!m_client->dashconnectComplete(m_connectionId, &identityId, &err)) {
            setStatus(tr("Could not complete login: %1").arg(err), true);
            return;
        }

        // The vault is NOT unlocked here; the caller unlocks it with `password`.
        emit ready(identityId, password);
        close();
    }

    void DashConnectLoginDialog::copyUri()
    {
        QApplication::clipboard()->setText(m_uri);
        setStatus(tr("URI copied to clipboard."));
    }

    void DashConnectLoginDialog::cancel()
    {
        if (m_timer->isActive()) {
            m_timer->stop();
        }
    }

    void DashConnectLoginDialog::setStatus(const QString& text, bool error)
    {
        m_status->setText(text);
        m_status->setStyleSheet(error ? QStringLiteral("color: #b00020;") : QString());
    }
} // namespace PyxPass
