import csv
import json
import queue
import threading
import time
from AppNetAuditFusion import rules
from AppNetAuditFusion import netLog
from AppNetAuditFusion import baseLog
#from AppNetAuditFusion.auditparser import aduitd_log_parse
from AppNetAuditFusion.Neo4jConnector import Neo4jConnector
from AppNetAuditFusion.datasets import DataSet, DATASETCONFIG
import ijson


class CustomPriorityQueue(queue.Queue):
    def __init__(self, maxtime_size=5):
        super(CustomPriorityQueue, self).__init__()
        self.lock = threading.Lock()
        self.maxtime_size = maxtime_size

    def push(self, logs: [baseLog]):
        with self.lock:
            # 添加Log对象到队列
            for log in logs:
                self.put(log)

    def pop(self):
        with self.lock:
            if not self.empty():
                return self.get()
            else:
                return None

    def cleanup(self, current_time):
        ans = []
        while True:
            with self.lock:
                if not self.empty():
                    log = self.queue[0]
                    if float(current_time) - float(log.Timestamp) <= self.maxtime_size:
                        break
                    else:
                        log = self.get()
                        ans.append(log)
                else:
                    break
        return ans


class TimeWindow:
    def __init__(self, window_size=5):
        self.appQueues = []
        for i in range(len(DataSet.app_parsers)):
            self.appQueues.append(CustomPriorityQueue(maxtime_size=window_size))
        self.netQueue = CustomPriorityQueue(maxtime_size=window_size)
        # Neo4jConnector.setup()

    def build_connection(self):
        for i in range(len(self.appQueues)):
            typename = DataSet.app_parsers[i].__name__
            rules.connect(list(self.appQueues[i].queue), list(self.netQueue.queue), dataset=typename)

    def build_connection_offline(self, apploglist_list, netlog_list):
        for i in range(len(apploglist_list)):
            typename = DataSet.app_parsers[i].__name__ + "offline"
            rules.connect(apploglist_list[i], netlog_list, dataset=typename)


    def parserlog(self):
        # input: applogs,appparsers,netlog,netparser
        # output:[[app1logs],[app2logs]],[netlogs]
        # format:log,csv
        app_results = []
        net_result = []

        for _app_path, _app_parser in zip(DataSet.dataset.app_paths, DataSet.app_parsers):
            app_res = []
            if ".csv" in _app_path:
                with open(_app_path, 'r', encoding='utf-8') as f:
                    r = csv.reader(f)
                    for row in r:
                        app_res.append(_app_parser(row))
            else:
                with open(_app_path, 'r', encoding='utf-8') as f:
                    _logs = f.readlines()
                    if DataSet.dataset.name == 'Vim':
                        unique_lst = []
                        for log in _logs:
                            if log[31:] not in unique_lst:
                                app_res.append(_app_parser(log))
                                unique_lst.append(log[31:])
                    else:
                        for log in _logs:
                            app_res.append(_app_parser(log))
                
            app_results.append(app_res)
        
        if not DataSet.dataset.net_path:
            return app_results,[]

        if ".json" in DataSet.dataset.net_path:
            with open(DataSet.dataset.net_path, 'r', encoding='utf-8') as f:
                for json_obj in ijson.items(f, 'item'):
                    net_result.append(DataSet.jsonnet_parser(json_obj))
                #r = json.load(f)
                #for row in r:
                #    net_result.append(DataSet.jsonnet_parser(row))
        else:
            with open(DataSet.dataset.net_path, 'r', encoding='utf-8') as f:
                _logs = f.readlines()
                for log in _logs:
                    net_result.append(DataSet.net_parser(log))

        return app_results, net_result

    def run(self) -> object:
        apps_logs, net_logs = self.parserlog()
        apps = []
        nets = []
        
        for loglist in apps_logs:
            _app = []
            for log in loglist:
                if log._has_timestamp:
                    _app.append(log)
            apps.append(_app)

        if not net_logs:
            # 没有netlog
            # for app_logs in apps_logs:
                # Neo4jConnector.batch_insert(apps, DataSet.dataset.name + "_" + type(app_logs[0]).__name__)
            for app_log in apps:
                self.appQueues[0].push(app_log)
            self.build_connection()
            return apps,[]
        
        for log in net_logs:
            if log._has_timestamp:
                nets.append(log)
        '''
        index = 0
        for log in net_logs:
            #使用jsonnetlog的httpdata初始化app端口
            if log.http_data:
                apps[0][index].SrcPort = log.srcPort
                index += 1
        '''

        if DataSet.dataset.name == "Apache_Pgsql":
            self.build_connection_offline(apploglist_list=apps,netlog_list=nets)
            return apps,nets

        if DataSet.dataset.name == "ImageMagick" or DataSet.dataset.name == "ImageMagick-2016":
            self.build_connection_offline(apploglist_list=apps,netlog_list=nets)
            return apps,nets

        if DataSet.dataset.update_time_table:
            update_net_timestamp(nets, DataSet.dataset.update_time_table[0], DataSet.dataset.update_time_table[1])
        #print(nets[1435].Timestamp)
        apps_res = [[]for _ in range(len(apps))]
        net_res = []
        timelist1 = [float(nets[0].Timestamp)] + [float(i[0].Timestamp) for i in apps]
        current_time = min(timelist1)
        timelist2 = [float(nets[-1].Timestamp)] + [float(i[-1].Timestamp) for i in apps]
        end_time = max(timelist2)
        app_index_list = [0 for _ in range(len(apps))]
        net_index = 0
        while current_time < end_time:
            tmp_apps = [[]for _ in range(len(apps))]
            tmp_net = []
            for i in range(len(apps)):
                while app_index_list[i] < len(apps[i]) and apps[i][app_index_list[i]].Timestamp < current_time:
                    tmp_apps[i].append(apps[i][app_index_list[i]])
                    app_index_list[i] += 1
            while net_index < len(nets) and nets[net_index].Timestamp < current_time:
                tmp_net.append(nets[net_index])
                net_index += 1

            for i in range(len(apps)):
                self.appQueues[i].push(tmp_apps[i])
            self.netQueue.push(tmp_net)
            self.build_connection()
            for i in range(len(apps)):
                apps_res[i] = apps_res[i] + self.appQueues[i].cleanup(current_time)
            net_res = net_res + self.netQueue.cleanup(current_time)

            current_time += 1
        # print("to neo4j")

        # for app_logs in apps_res:
            # Neo4jConnector.batch_insert(app_logs, DataSet.dataset.name + "_" + type(app_logs[0]).__name__)
        # Neo4jConnector.batch_insert(net_res, DataSet.dataset.name + "_net")
        # cnt = 0
        # none_cnt = 0
        # check_label_set = set()
        # for parsed_logs in apps_res:
        #      print(len(apps_res))
        #      app_length = len(parsed_logs)
        #      for parsed_log in parsed_logs:
        #          check_label_set.add(parsed_log.label)
        #      if app_length != len(check_label_set):
        #         print('Check Failed')
        #         exit()
        #         print(parsed_log)
        #         print(f"Timestamp: {parsed_log.Timestamp}")
        #         print(f"Host: {parsed_log.Host}")
        #         print(f"Method: {parsed_log.Method}")
        #         print(f"Url: {parsed_log.Url}")
        #         print(f"ResponseCode: {parsed_log.ResponseCode}")
        #         print(f"TransferSize: {parsed_log.TransferSize}")
        #         print(f"Object: {parsed_log.object}")
        #         print(f"Subject: {parsed_log.subject}")
        #         print(f"Action: {parsed_log.action}")
        #         print(f"Payload: {parsed_log.payload}")
        #         print(f"Label: {parsed_log.label}")
        #         print(f"Log: {parsed_log.log}")
        #         if parsed_log.label != None:
        #             cnt += 1
        #         else:
        #             none_cnt += 1
        # print(cnt)
        # print(none_cnt)
        return apps_res, net_res

    def audit_run(self):
        lines = aduitd_log_parse(DataSet.dataset.audit_path)
        auditlist = []
        for line in lines:
            auditlist.append(DataSet.audit_parser(line))
        Neo4jConnector.batch_insert(auditlist, DataSet.dataset.name + "_audit")

    def delete_all(self):
        Neo4jConnector.delete_all()


def update_net_timestamp(logs: [netLog.NetworkLog], log_idx, time):
    """给定确定的一条日志的时间戳,推算上下日志的时
        log_idx:能确定时间的日志index
        time: 对应时间
    """
    if len(logs) == 0:
        return
    start_time = time
    for i in range(log_idx, 0, -1):
        start_time = start_time - logs[i].Timestamp
    for i in range(0, len(logs)):
        tmp = logs[i].Timestamp
        logs[i].Timestamp = start_time
        start_time += tmp


if __name__ == "__main__":
    """
        模拟流式输入
    """
    t = TimeWindow()
    ans = t.run()
    pq = CustomPriorityQueue()
