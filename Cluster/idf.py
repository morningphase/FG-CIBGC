from math import log
from typing import Tuple
from tf import get_tf

def get_idf(subgraphs: [[Tuple]], events: []):


    idf = {}
    S = len(subgraphs)+1
    for event in events:
        idf[event] = 0
        for subgraph in subgraphs:
            for edge in subgraph:
                if event == edge:
                    idf[event] += 1
                    break
    for k in idf.keys():
        idf[k] = float(log(float(S / (idf[k]+1)),10))

    return idf

def get_tf_idf(subgraphs: [[Tuple]], events: []):

    tf_idf = {}
    tf = get_tf(subgraphs, events)
    idf = get_idf(subgraphs, events)
    for k in idf.keys():
        tf_v = tf[k]
        idf_v = idf[k]
        tf_idf[k] = tf_v * idf_v
    return tf_idf

def get_mean(subgraphs: [[Tuple]], events: []):

    add = {}
    tf = get_tf(subgraphs, events)
    for k in tf.keys():
        add[k] = float(1)/ len(events)
    return add

if __name__ == '__main__':
    print(get_idf([[("abc", "bcd", "dcf"), ("123", "456", "789")],
                   [("123", "456", "789"), ("abc", "bcd", "dcf")],
                   [("abc", "bcd", "dcf")]],
                  [("abc", "bcd", "dcf"),("123", "456", "789")]))
