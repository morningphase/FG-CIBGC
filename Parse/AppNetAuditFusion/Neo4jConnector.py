from py2neo import Graph, Node, Relationship, NodeMatcher
import os, sys
import csv
import json
from AppNetAuditFusion.datasets import DataSet, DATASETCONFIG

sys.path.append("..")  # 模块父目录下的model文件中
import AppNetAuditFusion.apacheLog
from AppNetAuditFusion.utils import neo4j_url, neo4j_passwd
from AppNetAuditFusion.baseLog import ENTITYTYPE
def convert_quotes(dictionary):
    new_dict = json.dumps(dictionary)
    return new_dict

class Neo4jConnector:
    graph = None
    id = 0

    @classmethod
    def setup(cls):
        cls.graph = Graph(neo4j_url, auth=('neo4j', neo4j_passwd))

    @classmethod
    def batch_insert(cls, log_list: [AppNetAuditFusion.baseLog], log_type):
        """
        支持neo4j数据库的批量插入，通过csv的方式进行插入，需要先将输入的loglist转换成为csv文件，然后导入到neo4j数据库
        """

        def to_csv(logs: [AppNetAuditFusion.baseLog], _log_type):
            if not os.path.exists(_log_type):
                os.makedirs(_log_type)
            node_filename = os.path.join(_log_type, "entity.csv")
            rel_filename = os.path.join(_log_type, 'edge.csv')
            node_csvfile = open(node_filename, mode='w', newline='')
            rel_csvfile = open(rel_filename, mode='w', newline='')
            node_fieldnames = ['name', 'entity_type', 'entity_data']
            rel_fieldnames = ['object', 'subject', 'Timestamp', 'log_type', 'label', 'payload', 'log_data']
            node_write = csv.DictWriter(node_csvfile, fieldnames=node_fieldnames)
            rel_write = csv.DictWriter(rel_csvfile, fieldnames=rel_fieldnames)
            node_write.writeheader()
            rel_write.writeheader()

            node_set = {}
            rel_list = []
            for log in logs:
                nodelist = [log.object, log.subject]
                for _node in nodelist:
                    if _node.entity_name in node_set.keys():
                        if node_set.get(_node.entity_name).entity_data is None:
                            node_set[_node.entity_name] = _node
                    else:
                        node_set[_node.entity_name] = _node

                rel_list.append({'object': log.object.entity_name,
                                 'subject': log.subject.entity_name,
                                 'Timestamp': log.Timestamp,
                                 'log_type': log.action,
                                 'label': log.label,
                                 'payload': log.payload,
                                 'log_data': log.log})

            for _node in node_set.values():
                node_write.writerow(
                    {'name': _node.entity_name, 'entity_type': ENTITYTYPE.entity_type_map[_node.entity_type],
                     'entity_data': _node.entity_name if _node.entity_data is None else _node.entity_data})

            for _rel in rel_list:
                rel_write.writerow(_rel)

            return node_filename, rel_filename

        node_csvfile, rel_csvfile = to_csv(log_list, log_type)

        directory, _ = os.path.split(os.path.abspath(__file__))
        # entity_file = os.path.join(directory, node_csvfile)
        # rel_file = os.path.join(directory, rel_csvfile)

        entity_file = node_csvfile
        rel_file = rel_csvfile

        cql = f"""
            LOAD CSV WITH HEADERS FROM 'file:///{entity_file}' AS line 
                Merge(n:Node{{name:line.name,entity_type:line.entity_type}})
                ON MATCH SET n.entity_data = line.entity_data
            """
        rel_cql = f"""
            LOAD CSV WITH HEADERS FROM 'file:///{rel_file}' AS line 
                MATCH (subject:Node {{name: line.subject}})
                MATCH (object:Node {{name: line.object}})
                CREATE (object)-[rel:{log_type} {{log_type: line.log_type, Timestamp: line.Timestamp, label: line.label, 
                payload: line.payload, log_data: line.log_data}}]->(subject) 
            """
        cls.graph.run(cql)
        cls.graph.run(rel_cql)

    @classmethod
    def create_log_and_nodes(cls, log_list: [AppNetAuditFusion.apacheLog.ApacheLog], log_type):
        for log_data in log_list:
            # 检查Subject节点是否存在，如果不存在则创建
            subject_node = cls.graph.nodes.match("Node", name=log_data.subject.entity_name).first()
            if not subject_node:
                subject_node = Node("Node", name=log_data.subject.entity_name,
                                    entity_type=ENTITYTYPE.entity_type_map[log_data.subject.entity_type],
                                    entity_data=log_data.subject.entity_data)
                cls.graph.create(subject_node)
            elif subject_node["entity_data"] is None:
                subject_node["entity_data"] = log_data.subject.entity_data
                cls.graph.push(subject_node)

            # 检查Object节点是否存在，如果不存在则创建
            object_node = cls.graph.nodes.match("Node", name=log_data.object.entity_name).first()
            if not object_node:
                object_node = Node("Node", name=log_data.object.entity_name,
                                   entity_type=ENTITYTYPE.entity_type_map[log_data.object.entity_type],
                                   entity_data=log_data.object.entity_data)
                cls.graph.create(object_node)
            elif object_node["entity_data"] is None:
                object_node["entity_data"] = log_data.object.entity_data
                cls.graph.push(object_node)
            if log_list[0].label is None:
                cql = f"""
                MATCH (subject:Node {{name: '{log_data.subject.entity_name}'}})
                MATCH (object:Node {{name: '{log_data.object.entity_name}'}})
                CREATE (object)-[rel:{log_type} {{log_type: '{log_data.action}', Timestamp: '{log_data.Timestamp}', label: '{log_data.label}', payload: '{log_data.payload}', log_data: '{convert_quotes(log_data.log)}'}}]->(subject)
                """

            else:
                label = 'l' + str(log_data.label)

                print(label)
                cql = f"""
                MATCH (subject:Node {{name: '{log_data.subject.entity_name}'}})
                MATCH (object:Node {{name: '{log_data.object.entity_name}'}})
                CREATE (object)-[rel:{label} {{label: '{log_data.label}', log_type: '{log_data.action}', Timestamp: '{log_data.Timestamp}', payload: '{log_data.payload}', log_data: '{convert_quotes(log_data.log)}'}}]->(subject)
                """
                print(cql)

            cls.graph.run(cql)

    @classmethod
    def delete_all(cls):
        query = """
                MATCH (n)
                DETACH DELETE n
                """

        cls.graph.run(query)

    @classmethod
    def query_kg(cls, label_name):
        # 执行Cypher查询以获取特定标签的所有边的ID、源节点ID和目标节点ID
        query = f"""
        MATCH (source)-[r:{label_name}]->(target)
        RETURN ID(r) AS edge_id, ID(source) AS source_id, ID(target) AS target_id
        """

        result = cls.graph.run(query)
        result_set = set()

        # 提取并输出边的ID、源节点ID和目标节点ID
        for record in result:
            edge_id = record["edge_id"]
            source_id = record["source_id"]
            target_id = record["target_id"]
            result_set.add((source_id, target_id, edge_id))
        return result_set

    @classmethod
    def query_edge_ids(cls, label):
        # 执行Cypher查询以获取边的名称和对应的边ID
        query = f"""
        MATCH (source)-[r:{label}]->(target)
        RETURN r.log_type AS edge_name, ID(r) AS edge_id, source.name as source_name, target.name as target_name
        """

        result = cls.graph.run(query)
        result_set = set()
        edge_name_set = set()
        node_name_set = set()
        original_triple = set()

        # 提取并输出边的名称和对应的边ID
        for record in result:
            edge_name = record["edge_name"]
            source_name = record["source_name"]
            target_name = record["target_name"]
            edge_name = edge_name
            edge_id = record["edge_id"]
            result_set.add((edge_name, edge_id))
            edge_name_set.add(edge_name)
            node_name_set.add(source_name)
            node_name_set.add(target_name)
            original_triple.add((source_name, target_name, edge_name))
        return result_set, edge_name_set, node_name_set, original_triple

    @classmethod
    def query_node_ids(cls, label):
        # 执行Cypher查询以获取节点的名称和对应的节点ID
        query = f"""
        MATCH ()-[r:{label}]->(n)
        RETURN n.name AS node_name, ID(n) AS node_id
        """

        result = cls.graph.run(query)
        result_set = set()

        # 提取并输出节点的名称和对应的节点ID
        for record in result:
            node_name = record["node_name"]
            node_id = record["node_id"]
            result_set.add((node_name, node_id))
        return result_set

    @classmethod
    def query_node_types(cls, label):
        # 执行Cypher查询以获取节点类型为文件或套接字的节点名称和类型
        query = f"""
        MATCH ()-[r:{label}]->(n)
        WHERE n.nodeType IN ['file', 'socket']
        RETURN n.name AS node_name, n.nodeType AS node_type
        """

        result = cls.graph.run(query)
        result_set = set()

        # 提取并输出节点名称和节点类型
        for record in result:
            node_name = record["node_name"]
            node_type = record["node_type"]
            result_set.add((node_name, node_type))
        return result_set


if __name__ == '__main__':
    Neo4jConnector.setup()
    Neo4jConnector.delete_all()
    DataSet.select_data_set(DATASETCONFIG.VIM)
    with open(DataSet.dataset.app_path, 'r') as file1:
        app_logs = file1.readlines()
    apps = []
    for log in app_logs:
        apps.append(DataSet.app_parser(log))
    Neo4jConnector.batch_insert(apps, DataSet.dataset.name + "_app")
