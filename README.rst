==========================================================
HTTPie Plugin for IIJ GIO Storage & Analysis Service (DAG)
==========================================================

HTTPie_ に `IIJ GIO Storage & Analysis Service (DAG)`_ REST API 認証のシグネチャ生成機能を付加するプラグイン

.. _HTTPie: https://httpie.org/
.. _`IIJ GIO Storage & Analysis Service (DAG)`: http://www.iij.ad.jp/biz/storage/


インストール方法
----------------

* pip でインストールする場合::

    pip install httpie-dag


使い方
------

以下の auth-type が追加されていますので `-a (--auth) ACCESS_KEY_ID:SECRET_ACCESS_KEY` と合せて指定してください。

===========  ========================================================
auth-type    説明
===========  ========================================================
dag          DAG Authentication (Signature Version 2)
dag:v4       DAG Authentication (Signature Version 4)
aws          Amazon AWS Authentication (Signature Version 2)
aws:v4       Amazon AWS Authentication (Signature Version 4)
===========  ========================================================

* GET Service::

    $ http -v --auth-type dag -a AKID0000000000000000:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX GET https://storage-dag.iijgio.com

    GET / HTTP/1.1
    Accept: */*
    Accept-Encoding: gzip, deflate
    Authorization: IIJGIO EALI0XQJWQCBASHAKJYV:ksJtxARuojOhG1M7UX4P92LOJ9g=
    Connection: keep-alive
    Date: Fri, 28 Nov 2014 14:27:18 GMT
    Host: storage-dag.iijgio.com
    User-Agent: HTTPie/0.8.0
    
    
    
    HTTP/1.1 200 OK
    Connection: close
    Content-Length: 772
    Content-Type: application/xml
    Date: Fri, 28 Nov 2014 14:27:18 GMT
    Server: dag.iijgio.com
    x-iijgio-id-2: 41E589A2E62A4221AF4F3511ECB65E21
    x-iijgio-request-id: 41E589A2E62A4221AF4F3511ECB65E21
    
    <?xml version="1.0" ?>
    <ListAllMyBucketsResult xmlns="http://dag.iijgio.com/doc/2006-03-01/">
        <Owner>
            <DisplayName>test-account-16333850@iij.ad.jp</DisplayName>
            <ID>a9711b60d80dcd5951c0443a7a46b2649e95dabbb192410d4efa0104f2166a53</ID>
        </Owner>
        <Buckets>
            <Bucket>
                <Name>safari8</Name>
                <CreationDate>2014-11-27T01:41:54.000Z</CreationDate>
            </Bucket>
            <Bucket>
                <Name>chrome39</Name>
                <CreationDate>2014-11-26T14:01:19.000Z</CreationDate>
            </Bucket>
            <Bucket>
                <Name>firefox33</Name>
                <CreationDate>2014-11-26T14:00:42.000Z</CreationDate>
            </Bucket>
            <Bucket>
                <Name>yosinobu4</Name>
                <CreationDate>2014-11-26T10:57:48.000Z</CreationDate>
            </Bucket>
            <Bucket>
                <Name>yosinobu3</Name>
                <CreationDate>2014-11-23T10:37:48.000Z</CreationDate>
            </Bucket>
        </Buckets>
    </ListAllMyBucketsResult>

* PUT Bucket::

    $ http -v --auth-type dag -a AKID0000000000000000:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX PUT https://storage-dag.iijgio.com/mybucket

    PUT /mybucket HTTP/1.1
    Accept: */*
    Accept-Encoding: gzip, deflate
    Authorization: IIJGIO AKID0000000000000000:kf6umAzob1rvpWG0mWXCmCtCU/I=
    Connection: keep-alive
    Content-Length: 0
    Date: Fri, 28 Nov 2014 14:36:58 GMT
    Host: storage-dag.iijgio.com
    User-Agent: HTTPie/0.8.0
    
    
    
    HTTP/1.1 200 OK
    Connection: close
    Content-Length: 0
    Content-Type: text/plain
    Date: Fri, 28 Nov 2014 14:36:58 GMT
    Location: https://storage-dag.iijgio.com/mybucket
    Server: dag.iijgio.com
    x-iijgio-id-2: 37374CC4182D4B1384D5EBDA6D166BDC
    x-iijgio-request-id: 37374CC4182D4B1384D5EBDA6D166BDC
    x-iijgio-version-id: null

* PUT Object::

    $ echo "this is test." | http -v --auth-type dag -a AKID0000000000000000:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX PUT https://mybucket.storage-dag.iijgio.com/foo.txt
    
    PUT /foo.txt HTTP/1.1
    Accept: application/json
    Accept-Encoding: gzip, deflate
    Authorization: IIJGIO AKID0000000000000000:R939NI+H9u0BkD1s0qZXgFPV5U8=
    Connection: keep-alive
    Content-Length: 14
    Content-Type: application/json; charset=utf-8
    Date: Fri, 28 Nov 2014 14:38:16 GMT
    Host: mybucket.storage-dag.iijgio.com
    User-Agent: HTTPie/0.8.0
    
    this is test.
    
    HTTP/1.1 200 OK
    Connection: close
    Content-Length: 0
    Content-Type: text/plain
    Date: Fri, 28 Nov 2014 14:38:16 GMT
    ETag: "477cbe70ead82460e7669d1162ac4122"
    Server: dag.iijgio.com
    x-iijgio-id-2: 52899B29B3924D58A5AE173C6802353D
    x-iijgio-request-id: 52899B29B3924D58A5AE173C6802353D
    x-iijgio-version-id: null

* GET Object::

    $ http -v --auth-type dag -a AKID0000000000000000:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX GET http://mybucket.storage-dag.iijgio.com/foo.txt
    
    GET /foo.txt HTTP/1.1
    Accept: */*
    Accept-Encoding: gzip, deflate
    Authorization: IIJGIO AKID0000000000000000:OrdmgRC4tWUvyYdekSU4l4OqO54=
    Connection: keep-alive
    Date: Fri, 28 Nov 2014 14:38:45 GMT
    Host: mybucket.storage-dag.iijgio.com
    User-Agent: HTTPie/0.8.0
    
    
    
    HTTP/1.1 200 OK
    Connection: close
    Content-Length: 14
    Content-Type: application/json; charset=utf-8
    Date: Fri, 28 Nov 2014 14:38:46 GMT
    ETag: "477cbe70ead82460e7669d1162ac4122"
    Last-Modified: Fri, 28 Nov 2014 14:38:16 GMT
    Server: dag.iijgio.com
    x-iijgio-id-2: 0BB4EE2AD3D94686B9741B2BBE6635B0
    x-iijgio-request-id: 0BB4EE2AD3D94686B9741B2BBE6635B0
    x-iijgio-version-id: null
    
    this is test.
