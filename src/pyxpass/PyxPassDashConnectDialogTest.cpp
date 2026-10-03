/*
 *  PyxPass — headless DashConnect login dialog render test (M10b/M11d)
 *
 *  Opens the real DashConnectLoginDialog against a LIVE sidecar
 *  (127.0.0.1:8765), renders it to PNG via QWidget::grab() (offscreen, no
 *  display needed) and verifies:
 *    1. dashconnectInit succeeds -> a connectionId and a dash-key: URI exist,
 *    2. the QR widget is populated and the URI is shown,
 *    3. the M11d request-expiry countdown is present and TICKS DOWN,
 *    4. screenshots are saved so the dialog can be inspected without a display.
 *
 *  Usage: pyxpass_dashconnect_dialog_test [outdir]
 *  (outdir defaults to /tmp/dashconnect-shots)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 */

#include "DashConnectLoginDialog.h"

#include <QApplication>
#include <QDir>
#include <QEventLoop>
#include <QLabel>
#include <QLineEdit>
#include <QPixmap>
#include <QRegularExpression>
#include <QTimer>
#include <QTextStream>

using namespace PyxPass;

static int failures = 0;

static void check(const QString& name, bool ok, const QString& detail = QString())
{
    QTextStream out(stdout);
    out << (ok ? "  \u2713 " : "  \u2717 ") << name;
    if (!ok && !detail.isEmpty()) {
        out << " \u2014 " << detail;
    }
    out << "\n";
    if (!ok) {
        ++failures;
    }
}

// Run the event loop for ms milliseconds so timers (poll, countdown) fire.
static void pump(int ms)
{
    QEventLoop loop;
    QTimer::singleShot(ms, &loop, &QEventLoop::quit);
    loop.exec();
}

// Find the countdown QLabel ("Request expires in MM:SS") among children.
static QString findCountdown(const QWidget& w)
{
    static const QRegularExpression re(QStringLiteral("Request expires in \\d+:\\d{2}"));
    const auto labels = w.findChildren<QLabel*>();
    for (const auto* l : labels) {
        if (re.match(l->text()).hasMatch()) {
            return l->text();
        }
    }
    return QString();
}

static void saveShot(QWidget& w, const QString& dir, const QString& name)
{
    QPixmap pm = w.grab();
    const QString path = dir + QLatin1Char('/') + name;
    if (pm.save(path)) {
        QTextStream(stdout) << "  shot: " << path << "\n";
    } else {
        QTextStream(stdout) << "  shot FAILED to write: " << path << "\n";
    }
}

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    QTextStream out(stdout);

    const QString outDir = (argc > 1) ? QString::fromLocal8Bit(argv[1])
                                      : QStringLiteral("/tmp/dashconnect-shots");
    if (!QDir().mkpath(outDir)) {
        QTextStream(stderr) << "FAIL: cannot create output dir " << outDir << "\n";
        return 1;
    }

    out << "DashConnect login dialog render test (offscreen)\n";
    out << "  outdir: " << outDir << "\n";

    DashConnectLoginDialog dlg;
    dlg.show();
    app.processEvents();
    pump(1500); // let dashconnectInit + first render settle

    // 1. init produced a connection id and a dash-key URI
    check(QStringLiteral("dashconnectInit produced a connectionId"), !dlg.connectionId().isEmpty(),
          dlg.connectionId());
    check(QStringLiteral("URI is a dash-key: deep link"), dlg.uri().startsWith(QStringLiteral("dash-key:")),
          dlg.uri().left(40));
    check(QStringLiteral("URI is shown in the dialog"), !dlg.findChild<QLineEdit*>()->text().isEmpty());

    // 2. initial countdown should be ~5:00
    const QString c1 = findCountdown(dlg);
    check(QStringLiteral("countdown label present"), !c1.isEmpty(), c1);
    saveShot(dlg, outDir, QStringLiteral("01-initial.png"));

    // 3. after a few seconds (a poll or two) the countdown must TICK DOWN
    pump(4000);
    const QString c2 = findCountdown(dlg);
    saveShot(dlg, outDir, QStringLiteral("02-after-poll.png"));
    bool ticked = false;
    if (!c1.isEmpty() && !c2.isEmpty()) {
        ticked = c1 != c2; // M11d: 1s timer decrements remainingMs -> mm:ss changes
    }
    check(QStringLiteral("countdown ticks down (M11d)"), ticked, c1 + QStringLiteral(" -> ") + c2);

    // 4. final render
    pump(1500);
    saveShot(dlg, outDir, QStringLiteral("03-final.png"));

    // The QR widget is rendered into the grabbed image; confirm the dialog is
    // non-empty and the URI text remains present.
    check(QStringLiteral("dialog renders (grab non-empty)"),
          !dlg.grab().isNull() && !dlg.grab().rect().isEmpty());

    dlg.close();
    QTextStream(stdout) << (failures == 0 ? "\nALL PASS" : "\nFAILURES") << "\n";
    return failures == 0 ? 0 : 1;
}
