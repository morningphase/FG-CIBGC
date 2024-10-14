from math import log
from typing import List, Tuple


def get_tf(subgraphs: List[List[Tuple]], events: []) -> dict:
    """
    Calculate the Term Frequency (TF) for each event based on the given subgraphs.

    Parameters:
    - events (List[Tuple]): List of events.
    - subgraphs (List[List[Tuple]]): List of subgraphs.

    Returns:
    - tf (dict): Dictionary containing TF values for each event.
    """

    tf = {}
    for event in events:
        tf[event] = 0
        for subgraph in subgraphs:
            for edge in subgraph:
                if event == edge:
                    tf[event] += 1
                    break

    # Normalize TF values
    total_events = len(subgraphs)
    for k in tf.keys():
        tf[k] /= total_events

    return tf


if __name__ == '__main__':
    subgraphs = [
        [("abc", "bcd", "dcf"), ("123", "456", "789")],
        [("123", "456", "789"), ("abc", "bcd", "dcf")],
        [("abc", "bcd", "dcf")]
    ]

    events = [("abc", "bcd", "dcf"),("123", "456", "789")]

    print(get_tf(subgraphs, events))
