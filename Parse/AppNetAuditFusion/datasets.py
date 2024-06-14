import importlib


class DATASETCONFIG:
    class APACHE:
        _is_multi_scene = False
        name = "Apache"
        audit_path = "../Data/Apache/audit.log"
        app_paths = ["../Data/Apache/apache.log"]
        net_path = "../Data/Apache/net.log"
        app_parsers = [getattr(importlib.import_module('AppNetAuditFusion.apacheLog'), "ApacheLog")]
        update_time_table = [1353, 1682509875]

    class OPENSSH:
        _is_multi_scene = False
        name = "Openssh"
        audit_path = "../Data/Openssh/audit.log"
        app_paths = ["../Data/Openssh/openssh.log"]
        net_path = "../Data/Openssh/net.log"
        app_parsers = [getattr(importlib.import_module('AppNetAuditFusion.openSSHLog'), "OpenSSHLog")]
        update_time_table = [6951, 1684721565]

    class POSTGRESQL:
        _is_multi_scene = False
        name = "PostgreSql"
        audit_path = "../Data/PostgreSql/audit.log"
        app_paths =[ "../Data/PostgreSql/postgresql.log"]
        net_path = "../Data/PostgreSql/net.log"
        # to be change
        app_parsers = [getattr(importlib.import_module('AppNetAuditFusion.postgresqlLog'), "PostgresqlLog")]
        update_time_table = [1353, 1682509875]

    class PROFTPD:
        _is_multi_scene = False
        name = "Proftpd"
        audit_path = "../Data/Proftpd/audit.log"
        app_paths =[ "../Data/Proftpd/proftpd.log"]
        net_path = "../Data/Proftpd/net.log"
        # to be change
        app_parsers = [getattr(importlib.import_module('AppNetAuditFusion.proftpdLog'), "ProftpdLog")]
        update_time_table = []

    class REDIS:
        _is_multi_scene = False
        name = "Redis"
        audit_path = "../Data/Redis/audit.log"
        app_paths = ["../Data/Redis/redis.log"]
        net_path = "../Data/Redis/net.log"
        # to be change
        app_parsers = [getattr(importlib.import_module('AppNetAuditFusion.redisLog'), "RedisLog")]
        update_time_table = [3569, 1683210007.420631]

    class VIM:
        _is_multi_scene = False
        name = "Vim"
        audit_path = "../Data/Vim/audit.log"
        app_paths = ["../Data/Vim/vim.log"]
        net_path = None
        app_parsers = [getattr(importlib.import_module('AppNetAuditFusion.vimLog'), "VimLog")]
        update_time_table = []

    class PHP:
        _is_multi_scene = False
        name = "Php"
        audit_path = "../Data/php/audit.log"
        app_paths = ["../Data/php/apache.log"]
        net_path = "../Data/php/net.log"
        # to be change
        app_parsers = [getattr(importlib.import_module('AppNetAuditFusion.phpLog'), "PhpLog")]
        update_time_table = []

    class NGINX:
        _is_multi_scene = False
        name = "Nginx"
        audit_path = "../Data/Nginx/audit.log"
        app_paths = ["../Data/Nginx/nginx.log"]
        net_path = "../Data/Nginx/net.log"
        # to be change
        app_parsers = [getattr(importlib.import_module('AppNetAuditFusion.nginxLog'), "NginxLog")]
        update_time_table = [908, 1682509278]

    class MINIHTTPD:
        _is_multi_scene = False
        name = "MiniHttpd"
        audit_path = "../Data/MiniHttpd/audit.log"
        app_paths = ["../Data/MiniHttpd/mini_httpd.log"]
        net_path = "../Data/MiniHttpd/net.log"
        # to be change
        app_parsers = [getattr(importlib.import_module('AppNetAuditFusion.apacheLog'), "ApacheLog")]
        update_time_table = [1353, 1682509875]

    class APACHE_PGSQL:
        _is_multi_scene = True
        name = "Apache_Pgsql"
        audit_path = "../Data/Apache_Pgsql/audit.log"
        app1_path = "../Data/Apache_Pgsql/apache.log"
        app2_path = "../Data/Apache_Pgsql/pgsql.csv"
        net_path = "../Data/Apache_Pgsql/net.json"
        update_time_table = []
        app_paths = [app1_path, app2_path]
        app_parsers = []
        app_parsers.append(getattr(importlib.import_module('AppNetAuditFusion.apacheLog'), "ApacheLog"))
        app_parsers.append(getattr(importlib.import_module('AppNetAuditFusion.postgresqlLog'), "PostgresqlLog"))
        update_time_table = []

    class APACHE_PROFTPD:
        _is_multi_scene = True
        name = "Apache_Proftpd"
        audit_path = "../Data/APT/S1/audit.log"
        app1_path = "../Data/APT/S1/apache.log"
        app2_path = "../Data/APT/S1/proftpd.log"
        net_path = "../Data/APT/S1/net.log"
        update_time_table = []
        app_paths = [app1_path, app2_path]
        app_parsers = []
        app_parsers.append(getattr(importlib.import_module('AppNetAuditFusion.phpLog'), "PhpLog"))
        app_parsers.append(getattr(importlib.import_module('AppNetAuditFusion.proftpdLog'), "ProftpdLog"))

    class IMAGEMAGICK:
        _is_multi_scene = True
        name = "ImageMagick"
        audit_path = "../Data/ImageMagick/audit.log"
        app1_path = "../Data/ImageMagick/apache.log"
        app2_path = "../Data/ImageMagick/imagemagick.log"
        net_path = "../Data/ImageMagick/net.json"
        update_time_table = []
        app_paths = [app1_path, app2_path]
        app_parsers = []
        app_parsers.append(getattr(importlib.import_module('AppNetAuditFusion.apacheLog'), "ApacheLog"))
        app_parsers.append(getattr(importlib.import_module('AppNetAuditFusion.imageMagickLog'), "ImageMagickLog"))

    class IMAGEMAGICK2016:
        _is_multi_scene = True
        name = "ImageMagick-2016"
        audit_path = "../Data/ImageMagick-2016/audit.log"
        app1_path = "../Data/ImageMagick-2016/apache.log"
        app2_path = "../Data/ImageMagick-2016/imagemagick.log"
        net_path = "../Data/ImageMagick-2016/net.json"
        update_time_table = []
        app_paths = [app1_path, app2_path]
        app_parsers = []
        app_parsers.append(getattr(importlib.import_module('AppNetAuditFusion.apacheLog'), "ApacheLog"))
        app_parsers.append(getattr(importlib.import_module('AppNetAuditFusion.imageMagickLog'), "ImageMagickLog"))


class DataSet:
    # app_parsers 按顺序各个应用的解析器类
    _is_multi_scene = False
    dataset = None
    app_parsers = []
    audit_parser = None
    net_parser = None
    jsonnet_parser = None

    @classmethod
    def select_data_set(cls, dataset):
        cls.dataset = dataset
        cls.app_parsers = dataset.app_parsers
        cls.audit_parser = getattr(importlib.import_module('AppNetAuditFusion.auditLog'), "AuditLog")
        cls.net_parser = getattr(importlib.import_module('AppNetAuditFusion.netLog'), "NetworkLog")
        cls.jsonnet_parser = getattr(importlib.import_module('AppNetAuditFusion.jsonnetLog'), "JsonNetworkLog")


if __name__ == '__main__':
    DataSet.select_data_set(DATASETCONFIG.APACHE)
    line = '192.168.119.23 - - [26/Apr/2023:19:51:15 +0800] "POST /icons/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1" 200 2948'
    parsed_log = DataSet.app_parser(line)
    print(parsed_log)
