/*
 *  PyxPass — headless integration test (Milestone 7c)
 *
 *  Exercises the fork's PyxPass client + bridge against a LIVE sidecar
 *  (127.0.0.1:8765), proving "open from Platform -> edit -> save -> persist"
 *  works without the GUI or any .kdbx file.
 *
 *  Usage: pyxpass_headless_test <password>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 */

#include "PyxPassBridge.h"
#include "PyxPassClient.h"

#include "core/Database.h"
#include "core/Entry.h"
#include "core/Group.h"

#include <QCoreApplication>
#include <QJsonObject>
#include <QSharedPointer>
#include <QTextStream>

using namespace PyxPass;

static int fail(const QString& msg)
{
    QTextStream(stderr) << "FAIL: " << msg << "\n";
    return 1;
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);

    if (argc < 2) {
        return fail("usage: pyxpass_headless_test <password>");
    }
    const QString password = QString::fromLocal8Bit(argv[1]);

    Client client;

    // 1. ping
    QString err;
    if (!client.ping(&err)) {
        return fail("ping: " + err + " (is the sidecar running on 127.0.0.1:8765?)");
    }
    out << "ok: sidecar reachable\n";

    // 2. unlock -> full pull (metadata)
    QString metaId;
    QList<EntryMeta> metas;
    if (!client.unlock(password, &metaId, &metas)) {
        return fail("unlock: " + client.lastError());
    }
    out << "ok: unlocked, metaId=" << metaId << ", on-chain entries=" << metas.size() << "\n";

    // 3. fetch plaintext for every entry
    QList<QJsonObject> docs;
    for (const auto& m : metas) {
        auto o = client.getEntry(m.entryId, &err);
        if (o.isEmpty()) {
            return fail("getEntry " + m.entryId + ": " + err);
        }
        o.insert(QStringLiteral("pyxpassId"), m.entryId);
        docs.append(o);
    }

    // 4. hydrate an in-memory Database (Open from Platform)
    auto db = QSharedPointer<Database>::create();
    hydrateDatabase(db, docs);
    const auto rootEntries = db->rootGroup()->entries();
    out << "ok: hydrated database with " << rootEntries.size() << " entries\n";

    // 5. create a NEW entry and persist it (Save to Platform)
    auto* ne = new Entry();
    ne->setTitle(QStringLiteral("pyxpass-headless"));
    ne->setUsername(QStringLiteral("tester"));
    ne->setPassword(QStringLiteral("s3cret"));
    ne->setUrl(QStringLiteral("https://example.com"));
    ne->setNotes(QStringLiteral("headless integration test"));
    db->rootGroup()->addEntry(ne);
    const auto createdId = client.createEntry(toPlaintext(ne), &err);
    if (createdId.isEmpty()) {
        return fail("createEntry: " + err);
    }
    setEntryId(ne, createdId);
    out << "ok: created entry " << createdId << "\n";

    // 6. edit the new entry and persist (updateEntry -> LWW push)
    ne->setTitle(QStringLiteral("pyxpass-headless-v2"));
    ne->setPassword(QStringLiteral("s3cret-v2"));
    auto upd = client.updateEntry(createdId, toPlaintext(ne));
    if (!upd.ok) {
        return fail("updateEntry: " + upd.error);
    }
    out << "ok: updated entry (pushed=" << upd.pushed << ", conflict=" << upd.conflict << ")\n";

    // 7. re-read from chain to confirm persistence
    auto re = client.getEntry(createdId, &err);
    if (re.isEmpty()) {
        return fail("getEntry after update: " + err);
    }
    if (re.value(QStringLiteral("title")).toString() != QStringLiteral("pyxpass-headless-v2")) {
        return fail("persistence check: title did not round-trip");
    }
    out << "ok: change persisted on-chain (title round-tripped)\n";

    // 8. cleanup: delete the test entry so it doesn't pollute the vault
    if (!client.deleteEntry(createdId, &err)) {
        return fail("deleteEntry: " + err);
    }
    out << "ok: cleaned up test entry\n";

    // 9. lock
    if (!client.lock()) {
        return fail("lock: " + client.lastError());
    }
    out << "ok: locked\n";
    out << "ALL PASS\n";
    return 0;
}
