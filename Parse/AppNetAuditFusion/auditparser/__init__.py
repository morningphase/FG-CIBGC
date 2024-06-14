# -*----- coding: utf-8 -----*-
# -*-- author: @PetitFleur --*-
#  @time    ：2022/9/18  14:07
#  @file    ：auditd.py
#  @tool    ：PyCharm
# -*-------------------------*-

import os
from typing import Union

from Parse.AppNetAuditFusion.auditparser.parse import parse as auditd_parse


def auditd_log2default(filepath: str, filename: str, app_name: Union[str, None] = None) -> None:
    input_file = os.path.join(filepath, filename)
    output_file = os.path.join(
        filepath, f'{filename[:filename.find(".")]}.tsv')
    return auditd_parse(input_file, output_file, {app_name} if app_name else None)


def aduitd_log_parse(filepath: str, app_name: Union[str, None] = None) -> None:
    input_file = filepath
    output_file = 'test.tsv'
    return auditd_parse(input_file, output_file, {app_name} if app_name else None)
