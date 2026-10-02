/*
 *  PyxPass — Dash-backed password manager (KeePassXC fork)
 *
 *  PyxPassClient: thin HTTP JSON-RPC client for the Node.js sidecar
 *  (127.0.0.1:8765/rpc). The sidecar owns all Dash Platform crypto + CRUD;
 *  this client only sends/receives JSON over HTTP.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 */

#ifndef KEEPASSXC_PYXPASSCLIENT_H
#define KEEPASSXC_PYXPASSCLIENT_H

#include <QJsonObject>
#include <QList>
#include <QString>
#include <QUrl>

class QNetworkAccessManager;
class QNetworkReply;

namespace PyxPass
{
    /** One entry as reported by the sidecar (metadata only). */
    struct EntryMeta
    {
        QString entryId;
        qint64 updatedAt = 0;
    };

    /** Result of an updateEntry RPC call. */
    struct UpdateResult
    {
        bool ok = false;
        bool pushed = false;
        bool conflict = false;
        QString resolved; // "remote" | "remote-deleted" | "" when local wins
        QString error;
    };

    /** Result of a save RPC call. */
    struct SaveResult
    {
        bool ok = false;
        QStringList pushed;
        QList<QPair<QString, QString>> conflicts; // entryId, resolved
        QString error;
    };

    /**
     * Identity confirmation data for a ready DashConnect request (M11a).
     * Shown BEFORE completing the login so the user can verify who answered.
     */
    struct ConfirmationData
    {
        bool ok = false;
        QString identityId; // full, unshortened
        QString dpnsName; // empty when none
        qint64 dpnsRegisteredAt = 0;
        bool isNewIdentity = false;
        bool isNameRecent = false;
        bool noDpnsName = false;
        QString error;
    };

    /**
     * Blocking HTTP JSON-RPC client for the PyxPass sidecar.
     * Calls are synchronous (spins a local QEventLoop) so it slots cleanly
     * into the fork's existing Database load/save flow.
     */
    class Client
    {
    public:
        explicit Client(const QUrl& baseUrl = QUrl(QStringLiteral("http://127.0.0.1:8765")));
        ~Client();

        bool ping(QString* err = nullptr);
        bool isConnected() const { return m_connected; }

        /** unlock -> { ok, metaId, entries:[{entryId, updatedAt}], identityId } */
        bool unlock(const QString& password, QString* metaId = nullptr, QList<EntryMeta>* entries = nullptr);
        bool lock();
        bool listEntries(QList<EntryMeta>* entries = nullptr);

        /** Fetch decrypted plaintext of one entry as a JSON object. */
        QJsonObject getEntry(const QString& entryId, QString* err = nullptr);

        QString createEntry(const QJsonObject& plaintext, QString* err = nullptr);
        UpdateResult updateEntry(const QString& entryId, const QJsonObject& plaintext);
        bool deleteEntry(const QString& entryId, QString* err = nullptr);
        SaveResult save();

        /** DashConnect (M10b): app-side login via a Dash wallet. */
        bool dashconnectInit(const QString& appContractId,
                             const QString& label,
                             QString* connectionId = nullptr,
                             QString* uri = nullptr,
                             QString* err = nullptr);
        bool dashconnectPoll(const QString& connectionId,
                             QString* status = nullptr,
                             QString* identityId = nullptr,
                             QString* err = nullptr);
        bool dashconnectComplete(const QString& connectionId,
                                 QString* identityId = nullptr,
                                 QString* err = nullptr);
        /** Fetch identity confirmation data for a ready request (M11a). */
        ConfirmationData dashconnectConfirmation(const QString& connectionId);

        QString lastError() const { return m_lastError; }

    private:
        QJsonObject call(const QString& method, const QJsonArray& params, QString* err = nullptr);
        QJsonObject sendRaw(const QByteArray& body, QString* err = nullptr);
        static void parseEntryMetas(const QJsonArray& arr, QList<EntryMeta>* out);
        void setErr(QString* err, const QString& msg);

        QUrl m_url;
        QNetworkAccessManager* m_nam = nullptr;
        QList<QNetworkReply*> m_replies; // outstanding replies
        bool m_connected = false;
        QString m_lastError;
    };
} // namespace PyxPass

#endif // KEEPASSXC_PYXPASSCLIENT_H
