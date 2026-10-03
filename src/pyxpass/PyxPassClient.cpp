/*
 *  PyxPass — Dash-backed password manager (KeePassXC fork)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 */

#include "PyxPassClient.h"

#include <QEventLoop>
#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>

namespace PyxPass
{
    Client::Client(const QUrl& baseUrl)
        : m_url(baseUrl)
        , m_nam(new QNetworkAccessManager())
    {
        m_url.setPath(QStringLiteral("/rpc"));
    }

    Client::~Client()
    {
        for (auto* reply : m_replies) {
            reply->abort();
        }
        m_replies.clear();
        delete m_nam;
    }

    QJsonObject Client::sendRaw(const QByteArray& body, QString* err)
    {
        QNetworkRequest req(m_url);
        req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
        req.setTransferTimeout(120000); // ms; Argon2 + chain RPC can be slow

        QNetworkReply* reply = m_nam->post(req, body);
        m_replies.append(reply);
        QObject::connect(reply, &QNetworkReply::finished, reply, [reply]() { /* noop; loop below exits */ });

        QEventLoop loop;
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        loop.exec();

        m_replies.removeAll(reply);
        const QByteArray data = reply->readAll();
        const auto error = reply->error();
        const QString errorString = reply->errorString();
        reply->deleteLater();

        if (error != QNetworkReply::NoError) {
            setErr(err, QStringLiteral("sidecar request failed: %1").arg(errorString));
            return {};
        }
        auto doc = QJsonDocument::fromJson(data);
        if (!doc.isObject()) {
            setErr(err, QStringLiteral("sidecar returned non-JSON"));
            return {};
        }
        return doc.object();
    }

    QJsonObject Client::call(const QString& method, const QJsonArray& params, QString* err)
    {
        QJsonObject req;
        req.insert(QStringLiteral("jsonrpc"), QStringLiteral("2.0"));
        req.insert(QStringLiteral("id"), 1);
        req.insert(QStringLiteral("method"), method);
        req.insert(QStringLiteral("params"), params);

        auto resp = sendRaw(QJsonDocument(req).toJson(QJsonDocument::Compact), err);
        if (resp.isEmpty()) {
            return {};
        }
        if (resp.contains(QStringLiteral("error"))) {
            auto e = resp.value(QStringLiteral("error")).toObject();
            setErr(err, e.value(QStringLiteral("message")).toString());
            return {};
        }
        return resp.value(QStringLiteral("result")).toObject();
    }

    bool Client::ping(QString* err)
    {
        auto res = call(QStringLiteral("ping"), {}, err);
        if (res.isEmpty()) {
            m_connected = false;
            return false;
        }
        m_connected = res.value(QStringLiteral("connected")).toBool();
        if (!m_connected) {
            setErr(err, QStringLiteral("sidecar not connected to network"));
        }
        return m_connected;
    }

    bool Client::unlock(const QString& password, QString* metaId, QList<EntryMeta>* entries)
    {
        m_lastError.clear();
        QJsonArray params;
        params.append(password);
        auto res = call(QStringLiteral("unlock"), params, &m_lastError);
        if (res.isEmpty() || !res.value(QStringLiteral("ok")).toBool()) {
            return false;
        }
        if (metaId) {
            *metaId = res.value(QStringLiteral("metaId")).toString();
        }
        if (entries) {
            parseEntryMetas(res.value(QStringLiteral("entries")).toArray(), entries);
        }
        return true;
    }

    bool Client::lock()
    {
        m_lastError.clear();
        auto res = call(QStringLiteral("lock"), {}, &m_lastError);
        return !res.isEmpty() && res.value(QStringLiteral("ok")).toBool();
    }

    bool Client::listEntries(QList<EntryMeta>* entries)
    {
        m_lastError.clear();
        auto res = call(QStringLiteral("listEntries"), {}, &m_lastError);
        if (res.isEmpty() || !res.value(QStringLiteral("ok")).toBool()) {
            return false;
        }
        if (entries) {
            parseEntryMetas(res.value(QStringLiteral("entries")).toArray(), entries);
        }
        return true;
    }

    QJsonObject Client::getEntry(const QString& entryId, QString* err)
    {
        m_lastError.clear();
        QJsonArray params;
        params.append(entryId);
        auto res = call(QStringLiteral("getEntry"), params, &m_lastError);
        if (res.isEmpty() || !res.value(QStringLiteral("ok")).toBool()) {
            if (err) {
                *err = m_lastError;
            }
            return {};
        }
        return res.value(QStringLiteral("entry")).toObject();
    }

    QString Client::createEntry(const QJsonObject& plaintext, QString* err)
    {
        m_lastError.clear();
        QJsonArray params;
        params.append(plaintext);
        auto res = call(QStringLiteral("createEntry"), params, &m_lastError);
        if (res.isEmpty() || !res.value(QStringLiteral("ok")).toBool()) {
            if (err) {
                *err = m_lastError;
            }
            return {};
        }
        return res.value(QStringLiteral("entryId")).toString();
    }

    UpdateResult Client::updateEntry(const QString& entryId, const QJsonObject& plaintext)
    {
        m_lastError.clear();
        UpdateResult out;
        QJsonArray params;
        params.append(entryId);
        params.append(plaintext);
        auto res = call(QStringLiteral("updateEntry"), params, &m_lastError);
        if (res.isEmpty() || !res.value(QStringLiteral("ok")).toBool()) {
            out.error = m_lastError;
            return out;
        }
        out.ok = true;
        out.pushed = res.value(QStringLiteral("pushed")).toBool();
        out.conflict = res.value(QStringLiteral("conflict")).toBool();
        auto conflicts = res.value(QStringLiteral("conflicts")).toArray();
        if (out.conflict && !conflicts.isEmpty()) {
            auto c = conflicts.first().toObject();
            out.resolved = c.value(QStringLiteral("resolved")).toString();
        }
        return out;
    }

    bool Client::deleteEntry(const QString& entryId, QString* err)
    {
        m_lastError.clear();
        QJsonArray params;
        params.append(entryId);
        auto res = call(QStringLiteral("deleteEntry"), params, &m_lastError);
        return !res.isEmpty() && res.value(QStringLiteral("ok")).toBool();
    }

    SaveResult Client::save()
    {
        m_lastError.clear();
        SaveResult out;
        auto res = call(QStringLiteral("save"), {}, &m_lastError);
        if (res.isEmpty() || !res.value(QStringLiteral("ok")).toBool()) {
            out.error = m_lastError;
            return out;
        }
        out.ok = true;
        for (const auto& v : res.value(QStringLiteral("pushed")).toArray()) {
            out.pushed.append(v.toString());
        }
        for (const auto& v : res.value(QStringLiteral("conflicts")).toArray()) {
            auto c = v.toObject();
            out.conflicts.append(qMakePair(c.value(QStringLiteral("entryId")).toString(),
                                           c.value(QStringLiteral("resolved")).toString()));
        }
        return out;
    }

    bool Client::dashconnectInit(const QString& appContractId,
                                 const QString& label,
                                 QString* connectionId,
                                 QString* uri,
                                 QString* err)
    {
        m_lastError.clear();
        QJsonArray params;
        params.append(appContractId);
        params.append(label);
        auto res = call(QStringLiteral("dashconnectInit"), params, &m_lastError);
        if (res.isEmpty()) {
            if (err) {
                *err = m_lastError;
            }
            return false;
        }
        if (connectionId) {
            *connectionId = res.value(QStringLiteral("connectionId")).toString();
        }
        if (uri) {
            *uri = res.value(QStringLiteral("uri")).toString();
        }
        return true;
    }

    bool Client::dashconnectPoll(const QString& connectionId,
                                 QString* status,
                                 QString* identityId,
                                 QString* err,
                                 qint64* remainingMs)
    {
        m_lastError.clear();
        QJsonArray params;
        params.append(connectionId);
        auto res = call(QStringLiteral("dashconnectPoll"), params, &m_lastError);
        if (res.isEmpty()) {
            if (err) {
                *err = m_lastError;
            }
            return false;
        }
        if (status) {
            *status = res.value(QStringLiteral("status")).toString();
        }
        if (identityId) {
            *identityId = res.value(QStringLiteral("identityId")).toString();
        }
        if (remainingMs) {
            *remainingMs = res.value(QStringLiteral("remainingMs")).toVariant().toLongLong();
        }
        return true;
    }

    bool Client::dashconnectComplete(const QString& connectionId,
                                     QString* identityId,
                                     QString* err)
    {
        m_lastError.clear();
        QJsonArray params;
        params.append(connectionId);
        auto res = call(QStringLiteral("dashconnectComplete"), params, &m_lastError);
        if (res.isEmpty() || !res.value(QStringLiteral("ok")).toBool()) {
            if (err) {
                *err = m_lastError;
            }
            return false;
        }
        if (identityId) {
            *identityId = res.value(QStringLiteral("identityId")).toString();
        }
        return true;
    }

    ConfirmationData Client::dashconnectConfirmation(const QString& connectionId)
    {
        ConfirmationData data;
        m_lastError.clear();
        QJsonArray params;
        params.append(connectionId);
        auto res = call(QStringLiteral("dashconnectConfirmation"), params, &m_lastError);
        if (res.isEmpty() || !res.value(QStringLiteral("ok")).toBool()) {
            data.error = m_lastError;
            return data;
        }
        data.ok = true;
        data.identityId = res.value(QStringLiteral("identityId")).toString();
        data.dpnsName = res.value(QStringLiteral("dpnsName")).toString();
        data.dpnsRegisteredAt = res.value(QStringLiteral("dpnsRegisteredAt")).toVariant().toLongLong();
        data.isNewIdentity = res.value(QStringLiteral("isNewIdentity")).toBool();
        data.isNameRecent = res.value(QStringLiteral("isNameRecent")).toBool();
        data.noDpnsName = res.value(QStringLiteral("noDpnsName")).toBool();
        return data;
    }

    void Client::parseEntryMetas(const QJsonArray& arr, QList<EntryMeta>* out)
    {
        for (const auto& v : arr) {
            auto o = v.toObject();
            EntryMeta m;
            m.entryId = o.value(QStringLiteral("entryId")).toString();
            m.updatedAt = o.value(QStringLiteral("updatedAt")).toVariant().toLongLong();
            out->append(m);
        }
    }

    void Client::setErr(QString* err, const QString& msg)
    {
        m_lastError = msg;
        if (err) {
            *err = msg;
        }
    }
} // namespace PyxPass
