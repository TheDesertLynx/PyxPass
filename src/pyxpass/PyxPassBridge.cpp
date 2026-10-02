/*
 *  PyxPass — Dash-backed password manager (KeePassXC fork)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 */

#include "PyxPassBridge.h"

#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"

#include <QJsonArray>

namespace PyxPass
{
    static QString field(const QJsonObject& o, const QString& key)
    {
        return o.value(key).toString();
    }

    QJsonObject toPlaintext(Entry* entry)
    {
        QJsonObject o;
        o.insert(QStringLiteral("title"), entry->title());
        o.insert(QStringLiteral("username"), entry->username());
        o.insert(QStringLiteral("password"), entry->password());
        o.insert(QStringLiteral("url"), entry->url());
        o.insert(QStringLiteral("notes"), entry->notes());
        const QString tags = entry->attributes()->value(QStringLiteral("Tags"));
        if (!tags.isEmpty()) {
            o.insert(QStringLiteral("tags"), tags);
        }
        const QString pid = entryId(entry);
        if (!pid.isEmpty()) {
            o.insert(QStringLiteral("pyxpassId"), pid);
        }
        return o;
    }

    void setEntryId(Entry* entry, const QString& entryId)
    {
        entry->attributes()->set(kEntryIdAttr, entryId);
    }

    QString entryId(Entry* entry)
    {
        return entry->attributes()->value(kEntryIdAttr);
    }

    void hydrateDatabase(QSharedPointer<Database> db, const QList<QJsonObject>& docs)
    {
        Group* root = ensureRootGroup(db);
        for (const auto& o : docs) {
            auto* entry = new Entry();
            entry->setGroup(root);
            entry->setTitle(field(o, QStringLiteral("title")));
            entry->setUsername(field(o, QStringLiteral("username")));
            entry->setPassword(field(o, QStringLiteral("password")));
            entry->setUrl(field(o, QStringLiteral("url")));
            entry->setNotes(field(o, QStringLiteral("notes")));
            const QString tags = field(o, QStringLiteral("tags"));
            if (!tags.isEmpty()) {
                entry->attributes()->set(QStringLiteral("Tags"), tags);
            }
            const QString pid = field(o, QStringLiteral("pyxpassId"));
            if (!pid.isEmpty()) {
                setEntryId(entry, pid);
            }
            root->addEntry(entry);
        }
    }

    Group* ensureRootGroup(QSharedPointer<Database> db)
    {
        Group* root = db->rootGroup();
        if (!root) {
            root = new Group();
            root->setName(kRootGroupName);
            db->setRootGroup(root);
        } else if (root->name() != kRootGroupName) {
            // Keep the existing root but rename to the Platform marker so the
            // UI reads naturally; entries live under it.
            root->setName(kRootGroupName);
        }
        return root;
    }
} // namespace PyxPass
