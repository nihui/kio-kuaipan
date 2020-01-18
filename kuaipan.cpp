/*
 *  This file is part of kio_kuaipan, KIO slave for KingSoft KuaiPan
 *  Copyright (C) 2012 Ni Hui <shuizhuyuanluo@126.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of
 *  the License or (at your option) version 3 or any later version
 *  accepted by the membership of KDE e.V. (or its successor approved
 *  by the membership of KDE e.V.), which shall act as a proxy
 *  defined in Section 14 of version 3 of the license.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "kuaipan.h"

#include <QApplication>
#include <QBuffer>
#include <KComponentData>
#include <KConfigGroup>
#include <KDebug>
#include <KGlobal>
#include <KInputDialog>
#include <KIO/AccessManager>
#include <KIO/Job>
#include <KIO/SlaveConfig>
#include <KIO/StoredTransferJob>
#include <KToolInvocation>

#include "multipartdevice.h"

extern "C" int KDE_EXPORT kdemain(int argc, char **argv)
{
    QApplication app(argc, argv);
    KComponentData componentData("kio_kuaipan");

    if (argc != 4) {
        kWarning() << "Usage: kio_kuaipan protocol domain-socket1 domain-socket2";
        exit(-1);
    }

    KuaiPanProtocol slave(argv[2], argv[3]);
    slave.dispatchLoop();

    return 0;
}

static const char appRoot[] = "app_folder"; // "app_folder" or "kuaipan"
static const char consumerKey[] = "xc066hvr2pLCw4b2";
static const char consumerSecret[] = "yBVQuCM26NhlV728";

KuaiPanProtocol::KuaiPanProtocol(const QByteArray& pool, const QByteArray& app)
    : KIO::SlaveBase("kuaipan", pool, app)
{
    m_qoauth = new QOAuth::Interface(new KIO::AccessManager(this), this);
    m_qoauth->setConsumerKey(consumerKey);
    m_qoauth->setConsumerSecret(consumerSecret);
    m_qoauth->setRequestTimeout(10000);
    m_qoauth->setIgnoreSslErrors(true);

    KConfigGroup cg(KGlobal::config(), "OAuth");
    m_isAuthorized = cg.readEntry("Authorized", false);
    m_oauthToken = cg.readEntry("OAuthToken", QByteArray());
    m_oauthTokenSecret = cg.readEntry("OAuthTokenSecret", QByteArray());
}

KuaiPanProtocol::~KuaiPanProtocol()
{
}

void KuaiPanProtocol::get(const KUrl& url)
{
//     kWarning() << url;
    if (!authorize())
        return;

    QString apiUrl("http://api-content.dfs.kuaipan.cn/1/fileops/download_file");

    QOAuth::ParamMap params;
    params.insert("root", appRoot);
    params.insert("path", url.path().toUtf8().toPercentEncoding());
    QByteArray hs = m_qoauth->createParametersString(apiUrl, QOAuth::GET, m_oauthToken, m_oauthTokenSecret,
                    QOAuth::HMAC_SHA1, params, QOAuth::ParseForInlineQuery);

    KUrl remoteUrl(apiUrl);
    remoteUrl.setQuery(hs);

    KIO::TransferJob* job = KIO::get(remoteUrl, KIO::Reload, KIO::DefaultFlags);
    job->addMetaData("content-type", "Content-Type: application/x-www-form-urlencoded");
    connect(job, SIGNAL(mimetype(KIO::Job*, QString)), this, SLOT(slot_download_file_mimetype(KIO::Job*, QString)));
    connect(job, SIGNAL(data(KIO::Job*, QByteArray)), this, SLOT(slot_download_file_data(KIO::Job*, QByteArray)));
    connect(job, SIGNAL(result(KJob*)), this, SLOT(slot_download_file_result(KJob*)));

    job->exec();
}

#if 0
void KuaiPanProtocol::put(const KUrl& url, int _mode, KIO::JobFlags _flags)
{
    kWarning() << url;
    if (!authorize())
        return;

    {
        // step upload_locate
        QString apiUrl("http://api-content.dfs.kuaipan.cn/1/fileops/upload_locate");

        QOAuth::ParamMap params;
        QByteArray hs = m_qoauth->createParametersString(apiUrl, QOAuth::GET, m_oauthToken, m_oauthTokenSecret,
                        QOAuth::HMAC_SHA1, params, QOAuth::ParseForInlineQuery);

        KUrl remoteUrl(apiUrl);
        remoteUrl.setQuery(hs);

        KIO::StoredTransferJob* job = KIO::storedGet(remoteUrl, KIO::Reload, KIO::HideProgressInfo);
        job->addMetaData("content-type", "Content-Type: application/x-www-form-urlencoded");
        connect(job, SIGNAL(result(KJob*)), this, SLOT(slot_upload_locate(KJob*)));

        job->exec();
    }

    {
        kWarning() << m_upload_url;
        // step upload_file
        QString apiUrl(m_upload_url + "fileops/upload_file");

        QOAuth::ParamMap params;
        params.insert("root", appRoot);
        params.insert("path", url.path().toUtf8().toPercentEncoding());
        params.insert("overwrite", "True");// True False
        QByteArray rc = m_qoauth->createParametersString(apiUrl, QOAuth::POST, m_oauthToken, m_oauthTokenSecret,
                        QOAuth::HMAC_SHA1, params, QOAuth::ParseForInlineQuery);

        KUrl remoteUrl(apiUrl);
        remoteUrl.setQuery(rc);

        kWarning() << "buffer device";
        // Loop until we got 'dataEnd'
        QBuffer bufferdev;
        bufferdev.open(QIODevice::ReadWrite);
        int result;
        QByteArray _data;
        do {
            dataReq(); // Request for data
            result = readData(_data);
            if(result > 0) {
                bufferdev.write(_data);
                while(bufferdev.bytesToWrite())
                    bufferdev.waitForBytesWritten(-1);
            }
        }
        while(result > 0);
        kWarning() << "buffer device end";

        MultiPartDevice mpd(bufferdev, 0);
        mpd.open(QIODevice::ReadOnly);
        QByteArray boundary("AaB03x");
        QByteArray fn = url.path().section('/', -1, -1, QString::SectionSkipEmpty).toUtf8().toPercentEncoding();
        mpd.setBoundary(boundary);
        mpd.setContentDispositionHeader("form-data; name=\"file\"; filename=\"" + fn + "\"");
        mpd.setContentTypeHeader("application/octet-stream");

        KIO::TransferJob* job = KIO::storedHttpPost(&mpd, remoteUrl, -1, KIO::DefaultFlags);
        job->addMetaData("content-type", "Content-Type: multipart/form-data; boundary=" + boundary);
        job->addMetaData("customHTTPHeader", "Accept-Encoding: identity");
        job->addMetaData("UserAgent", "klive");
        connect(job, SIGNAL(result(KJob*)), this, SLOT(slot_upload_file(KJob*)));

        job->exec();
    }
}
#endif

void KuaiPanProtocol::copy(const KUrl &src, const KUrl &dest, int mode, KIO::JobFlags flags)
{
//     kWarning() << src << dest << mode << flags;
    if (!authorize())
        return;

    if (src.isLocalFile() && !dest.isLocalFile()) {
        // local -> remote
        {
            // step upload_locate
            QString apiUrl("http://api-content.dfs.kuaipan.cn/1/fileops/upload_locate");

            QOAuth::ParamMap params;
            QByteArray hs = m_qoauth->createParametersString(apiUrl, QOAuth::GET, m_oauthToken, m_oauthTokenSecret,
                            QOAuth::HMAC_SHA1, params, QOAuth::ParseForInlineQuery);

            KUrl remoteUrl(apiUrl);
            remoteUrl.setQuery(hs);

            KIO::StoredTransferJob* job = KIO::storedGet(remoteUrl, KIO::Reload, KIO::HideProgressInfo);
            job->addMetaData("content-type", "Content-Type: application/x-www-form-urlencoded");
            connect(job, SIGNAL(result(KJob*)), this, SLOT(slot_upload_locate(KJob*)));

            job->exec();
        }

        {
            // step upload_file
            QString apiUrl(m_upload_url + "1/fileops/upload_file");

            QOAuth::ParamMap params;
            params.insert("root", appRoot);
            params.insert("path", dest.path().toUtf8().toPercentEncoding());
            params.insert("overwrite", "True");// True False
            QByteArray rc = m_qoauth->createParametersString(apiUrl, QOAuth::POST, m_oauthToken, m_oauthTokenSecret,
                            QOAuth::HMAC_SHA1, params, QOAuth::ParseForInlineQuery);

            KUrl remoteUrl(apiUrl);
            remoteUrl.setQuery(rc);

            QFile file(src.path());
            MultiPartDevice mpd(&file, 0);
            mpd.open(QIODevice::ReadOnly);
            QByteArray boundary("AaB03x");
            QByteArray fn = dest.path().section('/', -1, -1, QString::SectionSkipEmpty).toUtf8().toPercentEncoding();
            mpd.setBoundary(boundary);
            mpd.setContentDispositionHeader("form-data; name=\"file\"; filename=\"" + fn + "\"");
            mpd.setContentTypeHeader("application/octet-stream");

            KIO::TransferJob* job = KIO::storedHttpPost(&mpd, remoteUrl, -1, KIO::DefaultFlags);
            job->addMetaData("content-type", "Content-Type: multipart/form-data; boundary=" + boundary);
            job->addMetaData("customHTTPHeader", "Accept-Encoding: identity");
            job->addMetaData("UserAgent", "klive");
            connect(job, SIGNAL(result(KJob*)), this, SLOT(slot_upload_file(KJob*)));

            job->exec();
        }
        return;
    }

    if (!src.isLocalFile() && dest.isLocalFile()) {
        // remote -> local
        QString apiUrl("http://api-content.dfs.kuaipan.cn/1/fileops/download_file");

        QOAuth::ParamMap params;
        params.insert("root", appRoot);
        params.insert("path", src.path().toUtf8().toPercentEncoding());
        QByteArray hs = m_qoauth->createParametersString(apiUrl, QOAuth::GET, m_oauthToken, m_oauthTokenSecret,
                        QOAuth::HMAC_SHA1, params, QOAuth::ParseForInlineQuery);

        KUrl remoteUrl(apiUrl);
        remoteUrl.setQuery(hs);

        m_localFile.setFileName(dest.path());
        m_localFile.open(QIODevice::WriteOnly);

        KIO::TransferJob* job = KIO::get(remoteUrl, KIO::Reload, KIO::DefaultFlags);
        job->addMetaData("content-type", "Content-Type: application/x-www-form-urlencoded");
        connect(job, SIGNAL(mimetype(KIO::Job*, QString)), this, SLOT(slot_download_file_mimetype(KIO::Job*, QString)));
        connect(job, SIGNAL(data(KIO::Job*, QByteArray)), this, SLOT(slot_download_file_data(KIO::Job*, QByteArray)));
        connect(job, SIGNAL(result(KJob*)), this, SLOT(slot_download_file_result(KJob*)));

        job->exec();
        return;
    }

    // remote -> remote
    QString apiUrl("http://openapi.kuaipan.cn/1/fileops/copy");

    QOAuth::ParamMap params;
    params.insert("root", appRoot);
    params.insert("from_path", src.path().toUtf8().toPercentEncoding());
    params.insert("to_path", dest.path().toUtf8().toPercentEncoding());
    QByteArray hs = m_qoauth->createParametersString(apiUrl, QOAuth::GET, m_oauthToken, m_oauthTokenSecret,
                    QOAuth::HMAC_SHA1, params, QOAuth::ParseForInlineQuery);

    KUrl remoteUrl(apiUrl);
    remoteUrl.setQuery(hs);

    KIO::StoredTransferJob* job = KIO::storedGet(remoteUrl, KIO::Reload, KIO::HideProgressInfo);
    job->addMetaData("content-type", "Content-Type: application/x-www-form-urlencoded");
    connect(job, SIGNAL(result(KJob*)), this, SLOT(slot_filecopy(KJob*)));

    job->exec();
}

void KuaiPanProtocol::rename(const KUrl &src, const KUrl &dest, KIO::JobFlags flags)
{
//     kWarning() << src << dest << flags;
    if (!authorize())
        return;

    QString apiUrl("http://openapi.kuaipan.cn/1/fileops/move");

    QOAuth::ParamMap params;
    params.insert("root", appRoot);
    params.insert("from_path", src.path().toUtf8().toPercentEncoding());
    params.insert("to_path", dest.path().toUtf8().toPercentEncoding());
    QByteArray hs = m_qoauth->createParametersString(apiUrl, QOAuth::GET, m_oauthToken, m_oauthTokenSecret,
                    QOAuth::HMAC_SHA1, params, QOAuth::ParseForInlineQuery);

    KUrl remoteUrl(apiUrl);
    remoteUrl.setQuery(hs);

    KIO::StoredTransferJob* job = KIO::storedGet(remoteUrl, KIO::Reload, KIO::HideProgressInfo);
    job->addMetaData("content-type", "Content-Type: application/x-www-form-urlencoded");
    connect(job, SIGNAL(result(KJob*)), this, SLOT(slot_filemove(KJob*)));

    job->exec();
}

void KuaiPanProtocol::stat(const KUrl& url)
{
//     kWarning() << url;
    if (!authorize())
        return;

    if (url.path().length() <= 1) {
        // root path
        KIO::UDSEntry entry;
        entry.insert(KIO::UDSEntry::UDS_NAME, QString::fromLatin1("."));
        entry.insert(KIO::UDSEntry::UDS_FILE_TYPE, S_IFDIR);
        entry.insert(KIO::UDSEntry::UDS_MIME_TYPE, QLatin1String("inode/directory"));
        entry.insert(KIO::UDSEntry::UDS_ACCESS, S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

        statEntry(entry);
        finished();
        return;
    }

    QString apiUrl("http://openapi.kuaipan.cn/1/metadata/");
    apiUrl += appRoot;
    apiUrl += url.path().toUtf8().toPercentEncoding();

    QOAuth::ParamMap params;
    QByteArray hs = m_qoauth->createParametersString(apiUrl, QOAuth::GET, m_oauthToken, m_oauthTokenSecret,
                    QOAuth::HMAC_SHA1, params, QOAuth::ParseForInlineQuery);

    KUrl remoteUrl(apiUrl);
    remoteUrl.setQuery(hs);

    KIO::StoredTransferJob* job = KIO::storedGet(remoteUrl, KIO::Reload, KIO::HideProgressInfo);
    job->addMetaData("content-type", "Content-Type: application/x-www-form-urlencoded");
    connect(job, SIGNAL(result(KJob*)), this, SLOT(slot_stat_metadata(KJob*)));

    job->exec();
}

void KuaiPanProtocol::listDir(const KUrl& url)
{
//     kWarning() << url << url.path();
    if (!authorize())
        return;

    QString apiUrl("http://openapi.kuaipan.cn/1/metadata/");
    apiUrl += appRoot;
    apiUrl += url.path().toUtf8().toPercentEncoding();

    QOAuth::ParamMap params;
    QByteArray hs = m_qoauth->createParametersString(apiUrl, QOAuth::GET, m_oauthToken, m_oauthTokenSecret,
                    QOAuth::HMAC_SHA1, params, QOAuth::ParseForInlineQuery);

    KUrl remoteUrl(apiUrl);
    remoteUrl.setQuery(hs);

    KIO::StoredTransferJob* job = KIO::storedGet(remoteUrl, KIO::Reload, KIO::HideProgressInfo);
    job->addMetaData("content-type", "Content-Type: application/x-www-form-urlencoded");
    connect(job, SIGNAL(result(KJob*)), this, SLOT(slot_metadata(KJob*)));

    job->exec();
}

void KuaiPanProtocol::mkdir(const KUrl& url, int permissions)
{
//     kWarning() << url << permissions;
    if (!authorize())
        return;

    QString apiUrl("http://openapi.kuaipan.cn/1/fileops/create_folder");

    QOAuth::ParamMap params;
    params.insert("root", appRoot);
    params.insert("path", url.path().toUtf8().toPercentEncoding());
    QByteArray hs = m_qoauth->createParametersString(apiUrl, QOAuth::GET, m_oauthToken, m_oauthTokenSecret,
                    QOAuth::HMAC_SHA1, params, QOAuth::ParseForInlineQuery);

    KUrl remoteUrl(apiUrl);
    remoteUrl.setQuery(hs);

    KIO::StoredTransferJob* job = KIO::storedGet(remoteUrl, KIO::Reload, KIO::HideProgressInfo);
    job->addMetaData("content-type", "Content-Type: application/x-www-form-urlencoded");
    connect(job, SIGNAL(result(KJob*)), this, SLOT(slot_create_folder(KJob*)));

    job->exec();
}

void KuaiPanProtocol::del(const KUrl& url, bool isfile)
{
//     kWarning() << url << isfile;
    if (!authorize())
        return;

    QString apiUrl("http://openapi.kuaipan.cn/1/fileops/delete");

    QOAuth::ParamMap params;
    params.insert("root", appRoot);
    params.insert("path", url.path().toUtf8().toPercentEncoding());
    QByteArray hs = m_qoauth->createParametersString(apiUrl, QOAuth::GET, m_oauthToken, m_oauthTokenSecret,
                    QOAuth::HMAC_SHA1, params, QOAuth::ParseForInlineQuery);

    KUrl remoteUrl(apiUrl);
    remoteUrl.setQuery(hs);

    KIO::StoredTransferJob* job = KIO::storedGet(remoteUrl, KIO::Reload, KIO::HideProgressInfo);
    job->addMetaData("content-type", "Content-Type: application/x-www-form-urlencoded");
    connect(job, SIGNAL(result(KJob*)), this, SLOT(slot_filedelete(KJob*)));

    job->exec();
}

bool KuaiPanProtocol::authorize()
{
    if (m_isAuthorized) {
        // already cached in slave
        return true;
    }

    {
        // load from kio_kuaipanrc
        KConfigGroup cg(KGlobal::config(), "OAuth");
        m_isAuthorized = cg.readEntry("Authorized", false);
        m_oauthToken = cg.readEntry("OAuthToken", QByteArray());
        m_oauthTokenSecret = cg.readEntry("OAuthTokenSecret", QByteArray());
    }

    if (m_isAuthorized) {
        // already authorized
        return true;
    }

    infoMessage("Start to authorize");

    // requestToken
    QOAuth::ParamMap requestTokenReply = m_qoauth->requestToken( "https://openapi.kuaipan.cn/open/requestToken",
                                                                 QOAuth::POST, QOAuth::HMAC_SHA1 );

    if ( m_qoauth->error() != QOAuth::NoError ) {
        kWarning() << "ERROR request token: " << m_qoauth->error();
        error(KIO::ERR_COULD_NOT_LOGIN, i18n("ERROR request token: %1", m_qoauth->error()));
        return false;
    }

    m_oauthToken = requestTokenReply.value( QOAuth::tokenParameterName() );
    m_oauthTokenSecret = requestTokenReply.value( QOAuth::tokenSecretParameterName() );

    if (m_oauthToken.isEmpty() || m_oauthTokenSecret.isEmpty()) {
        /// workaround
        bool ok;
        QVariantMap map = m_parser.parse( requestTokenReply.value(""), &ok ).toMap();
        m_oauthToken = map.value( QOAuth::tokenParameterName() ).toByteArray();
        m_oauthTokenSecret = map.value( QOAuth::tokenSecretParameterName() ).toByteArray();
    }

    // authorize
    KToolInvocation::invokeBrowser( "https://www.kuaipan.cn/api.php?ac=open&op=authorise&oauth_token=" + m_oauthToken );
    QString pintext = KInputDialog::getText(i18n("Enter the PIN code"), i18n("PIN code"));
    if (pintext.isEmpty()) {
        kWarning() << "pintext is empty";
        error(KIO::ERR_COULD_NOT_LOGIN, i18n("PIN code is empty"));
        return false;
    }

    // accessToken
    QOAuth::ParamMap params;
    params.insert( "oauth_verifier", pintext.toAscii() );
    QOAuth::ParamMap accessTokenReply = m_qoauth->accessToken( "https://openapi.kuaipan.cn/open/accessToken",
                                                               QOAuth::POST, m_oauthToken,
                                                               m_oauthTokenSecret, QOAuth::HMAC_SHA1, params );

    if ( m_qoauth->error() != QOAuth::NoError ) {
        kWarning() << "ERROR access token: " << m_qoauth->error();
        error(KIO::ERR_COULD_NOT_LOGIN, i18n("ERROR access token: %1", m_qoauth->error()));
        return false;
    }

    m_oauthToken = accessTokenReply.value( QOAuth::tokenParameterName() );
    m_oauthTokenSecret = accessTokenReply.value( QOAuth::tokenSecretParameterName() );

    if (m_oauthToken.isEmpty() || m_oauthTokenSecret.isEmpty()) {
        /// workaround
        bool ok;
        QVariantMap map = m_parser.parse( accessTokenReply.value(""), &ok ).toMap();
        m_oauthToken = map.value( QOAuth::tokenParameterName() ).toByteArray();
        m_oauthTokenSecret = map.value( QOAuth::tokenSecretParameterName() ).toByteArray();
    }

    kWarning() << "success!";
    infoMessage("Authorized");
    m_isAuthorized = true;

    {
        // save to kio_kuaipanrc
        KConfigGroup cg(KGlobal::config(), "OAuth");
        cg.writeEntry("Authorized", m_isAuthorized);
        cg.writeEntry("OAuthToken", m_oauthToken);
        cg.writeEntry("OAuthTokenSecret", m_oauthTokenSecret);
        cg.sync();
    }

    return true;
}

void KuaiPanProtocol::slot_download_file_mimetype(KIO::Job*, const QString& type)
{
//     kWarning() << type;
    emit mimeType(type);
}

void KuaiPanProtocol::slot_download_file_data(KIO::Job* job, const QByteArray& _data)
{
//     kWarning();
    if (m_localFile.isOpen()) {
        m_localFile.write(_data);
    }
    else {
        emit data(_data);
    }
}

void KuaiPanProtocol::slot_download_file_result(KJob* job)
{
//     kWarning();
    if (job->error()) {
        kWarning() << "Job Error: " << job->errorString();
        return;
    }

    m_localFile.close();

    finished();
}

void KuaiPanProtocol::slot_upload_locate(KJob* job)
{
//     kWarning();
    if (job->error()) {
        kWarning() << "Job Error: " << job->errorString();
        return;
    }

    KIO::StoredTransferJob* j = static_cast<KIO::StoredTransferJob*>(job);

    bool ok;
    QVariantMap map = m_parser.parse(j->data(), &ok).toMap();
    m_upload_url = map["url"].toString();
}

void KuaiPanProtocol::slot_upload_file(KJob* job)
{
//     kWarning();
    if (job->error()) {
        kWarning() << "Job Error: " << job->errorString();
        return;
    }

//     KIO::StoredTransferJob* j = static_cast<KIO::StoredTransferJob*>(job);
//     kWarning() << j->data();

    finished();
}

void KuaiPanProtocol::slot_filecopy(KJob* job)
{
//     kWarning();
    if (job->error()) {
        kWarning() << "Job Error: " << job->errorString();
        return;
    }

    finished();
}

void KuaiPanProtocol::slot_filemove(KJob* job)
{
//     kWarning();
    if (job->error()) {
        kWarning() << "Job Error: " << job->errorString();
        return;
    }

    finished();
}

void KuaiPanProtocol::slot_metadata(KJob* job)
{
    if (job->error()) {
        kWarning() << "Job Error: " << job->errorString();
        return;
    }

    KIO::StoredTransferJob* j = static_cast<KIO::StoredTransferJob*>(job);
//     kWarning() << j->data();

    bool ok;
    QVariantMap map = m_parser.parse(j->data(), &ok).toMap();
    QVariantList files = map["files"].toList();
    foreach(const QVariant & file, files) {
        QVariantMap filemap = file.toMap();

        KIO::UDSEntry entry;
        entry.insert(KIO::UDSEntry::UDS_NAME, filemap["name"].toString());
        entry.insert(KIO::UDSEntry::UDS_CREATION_TIME,
                     QDateTime::fromString(filemap["create_time"].toString(), "yyyy-MM-dd hh:mm:ss").toTime_t());
        entry.insert(KIO::UDSEntry::UDS_MODIFICATION_TIME,
                     QDateTime::fromString(filemap["modify_time"].toString(), "yyyy-MM-dd hh:mm:ss").toTime_t());
        if (filemap["type"].toString() == "folder") {
            entry.insert(KIO::UDSEntry::UDS_FILE_TYPE, S_IFDIR);
            entry.insert(KIO::UDSEntry::UDS_MIME_TYPE, QLatin1String("inode/directory"));
        }
        else {
            entry.insert(KIO::UDSEntry::UDS_FILE_TYPE, S_IFREG);
            entry.insert(KIO::UDSEntry::UDS_SIZE, filemap["size"].toInt());
        }
        entry.insert(KIO::UDSEntry::UDS_ACCESS, 0600);
        listEntry(entry, false);
    }

    KIO::UDSEntry entry;
    listEntry(entry, true);

    finished();
}

void KuaiPanProtocol::slot_stat_metadata(KJob* job)
{
    if(job->error()) {
        kWarning() << "Job Error: " << job->errorString();
        return;
    }

    KIO::StoredTransferJob* j = static_cast<KIO::StoredTransferJob*>(job);
//     kWarning() << j->data();

    bool ok;
    QVariantMap filemap = m_parser.parse(j->data(), &ok).toMap();

    KIO::UDSEntry entry;
    entry.insert(KIO::UDSEntry::UDS_NAME, filemap["name"].toString());
    entry.insert(KIO::UDSEntry::UDS_CREATION_TIME,
                 QDateTime::fromString(filemap["create_time"].toString(), "yyyy-MM-dd hh:mm:ss").toTime_t());
    entry.insert(KIO::UDSEntry::UDS_MODIFICATION_TIME,
                 QDateTime::fromString(filemap["modify_time"].toString(), "yyyy-MM-dd hh:mm:ss").toTime_t());
    if (filemap["type"].toString() == "folder") {
        entry.insert(KIO::UDSEntry::UDS_FILE_TYPE, S_IFDIR);
        entry.insert(KIO::UDSEntry::UDS_MIME_TYPE, QLatin1String("inode/directory"));
    }
    else {
        entry.insert(KIO::UDSEntry::UDS_FILE_TYPE, S_IFREG);
        entry.insert(KIO::UDSEntry::UDS_SIZE, filemap["size"].toInt());
    }
    entry.insert(KIO::UDSEntry::UDS_ACCESS, 0600);

    statEntry(entry);
    finished();
}

void KuaiPanProtocol::slot_create_folder(KJob* job)
{
//     kWarning();
    if (job->error()) {
        kWarning() << "Job Error: " << job->errorString();
        return;
    }

    finished();
}

void KuaiPanProtocol::slot_filedelete(KJob* job)
{
//     kWarning();
    if (job->error()) {
        kWarning() << "Job Error: " << job->errorString();
        return;
    }

    finished();
}
