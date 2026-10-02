/*
 *  PyxPass — Dash-backed password manager (KeePassXC fork)
 *
 *  PyxPassBridge: maps sidecar entry documents <-> KeePassXC Database entries.
 *  - hydrate(): build an in-memory Database from sidecar entries (Open from Platform)
 *  - toPlaintext()/persist(): push entry edits back to the sidecar (Save to Platform)
 *
 *  The sidecar is the SOLE source of truth: no .kdbx is ever written.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 */

#ifndef KEEPASSXC_PYXPASSBRIDGE_H
#define KEEPASSXC_PYXPASSBRIDGE_H

#include <QJsonObject>
#include <QSharedPointer>
#include <QString>

class Database;
class Entry;
class Group;

namespace PyxPass
{
    /** Attribute key that stores the on-chain entry id on a KeePassXC Entry. */
    const QString kEntryIdAttr = QStringLiteral("PyxPassEntryId");
    /** Root group name for entries opened from Platform. */
    const QString kRootGroupName = QStringLiteral("Platform");

    /** Serialize a KeePassXC Entry into the sidecar plaintext JSON schema. */
    QJsonObject toPlaintext(Entry* entry);

    /** Set the on-chain entry id attribute (empty -> new/unsaved entry). */
    void setEntryId(Entry* entry, const QString& entryId);
    QString entryId(Entry* entry);

    /**
     * Hydrate an empty Database from sidecar entry data.
     * Each doc in `docs` is the decrypted plaintext JSON object with an
     * optional "pyxpassId" field carrying the on-chain entry id.
     */
    void hydrateDatabase(QSharedPointer<Database> db, const QList<QJsonObject>& docs);

    /** Ensure the Database has a Platform root group, creating it if needed. */
    Group* ensureRootGroup(QSharedPointer<Database> db);
} // namespace PyxPass

#endif // KEEPASSXC_PYXPASSBRIDGE_H
