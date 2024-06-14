import re
from AppNetAuditFusion import baseLog
import time
import pytz
from datetime import datetime, timezone

class ImageMagickLog(baseLog.BaseLog):
    def __init__(self, log):
        super(ImageMagickLog, self).__init__()
        reg1 = r'.*\[(.*)\]:.*rights=(.*); pattern="(.*)"'
        match = re.search(reg1,log)
        if not match or match.group(3) == "PNG":
            self.Timestamp = None
            return

        self.Timestamp = self.get_imagemagick_timestamp(log)
        self.Pid = match.group(1)
        self.Rights = match.group(2)
        self.Path = match.group(3)
        self.File = match.group(3)
        
        self.to_baselog()
        self.log = self.to__dict()

    def get_imagemagick_timestamp(self, log):
        s = log.split(" ")[0]
        # 将时间戳字符串解析为datetime对象
        timestamp_dt = datetime.fromisoformat(s)
        # 转换为带时区信息的datetime对象（上海时区）
        timestamp_utc = timestamp_dt.astimezone(timezone.utc)

        # 转换为带时区信息的datetime对象
        #timestamp_with_timezone = timestamp_dt.replace(tzinfo=timezone.utc)

        # 获取Unix时间戳
        unix_timestamp = int(timestamp_utc.timestamp())
        return unix_timestamp

    def to_baselog(self):
        self.action = self.Rights
        if self.action == 'Write':
            self.subject.entity_name = self.Path
            self.subject.entity_type = baseLog.ENTITYTYPE.FILE
            self.object.entity_name = "ImageMagick.exe"
            self.object.entity_type = baseLog.ENTITYTYPE.PROCESS
        else:
            self.subject.entity_name = "ImageMagick.exe"
            self.subject.entity_type = baseLog.ENTITYTYPE.PROCESS
            self.object.entity_name = self.Path
            self.object.entity_type = baseLog.ENTITYTYPE.FILE
        self.payload = self.File

if __name__ == '__main__':
    line = '2024-01-22T15:55:47+08:00 0:00.000 0.000u 6.9.2 Policy identify[25009]: policy.c/IsRightsAuthorized/574/Policy  Domain: Path; rights=Read; pattern="/var/www/html/uploads/input_2.png" ...'
    parsed_log = ImageMagickLog(line)
    if parsed_log:
        print(f"Timestamp: {parsed_log.Timestamp}")
        print(f"Pid: {parsed_log.Pid}")
        print(f"Rights: {parsed_log.Rights}")
        print(f"Path: {parsed_log.Path}")
        print(f"File: {parsed_log.File}")
    else:
        print("Invalid log line")
