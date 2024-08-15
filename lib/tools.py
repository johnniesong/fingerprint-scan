import time,datetime

class Time:
    def __init__(self):
        self.sTime=None
        self.eTime=None
        self.start=None

    def now(self,format="%Y-%m-%d %H:%M:%S",is_UTC=False):
        if not is_UTC:
            return time.strftime(format, time.localtime(time.time()))
        else:
            return time.strftime(format, time.localtime(time.time()))

    def now_obj(self,format="%Y-%m-%d %H:%M:%S"):
        return datetime.datetime.strptime(time.strftime(format, time.localtime(time.time())),format)

    def day(self):
        return time.strftime("%Y-%m-%d", time.localtime(time.time()))

    def hour(self):
        return int(time.strftime("%H", time.localtime(time.time())))

    def consoleNow(self):
        return time.strftime("%a %b %d %H", time.localtime(time.time()))

    def getTimeByCustom(self,format,postime=0):
        return time.strftime(format, time.localtime(time.time()+postime))

    def getObjTime(self,strtime,format):
        return time.strptime(strtime,format)
    #Time().strTimeToDigital(Time().get_recentMinute(10),"%Y-%m-%d %H:%M:%S"):
    def strTimeToDigital(self,strtime,format="%Y %a %b %d %H:%M"):
        return time.mktime(time.strptime(strtime,format))

    def getDigitalTimeByCustom(self,postime=0):
        return time.localtime(time.time()+postime)

    def timestamps(self):
        return time.time()

    def year(self):
        return time.strftime("%Y", time.localtime(time.time()))

    def setStartTime(self):
        self.sTime=time.time()

    def setEndTime(self):
        self.eTime=time.time()

    def getCostTime(self):
        return self.eTime-self.sTime

    def printCostTime(self,mark=""):
        print("%s Cost Time : %s sec"%(mark,self.eTime-self.sTime))

    def printCostBigTime(self,mark="",big=3):
        cost=self.eTime-self.sTime
        if int(cost)>=big:
            print("%s Cost Time : %s sec"%(mark,cost))

    def is_passTime(self,intervalTime=3):#是否过了一定时间
        if time.time()-self.start>intervalTime:
            self.start=time.time()
            return 1
        else:
            return 0

    def timestampToString(self,timestamp,format="%Y-%m-%d %H:%M:%S"):
        if timestamp:
            timeArray = time.localtime(int(timestamp))
            stringTime = time.strftime(format, timeArray)
            return stringTime
        else:
            return None

    def get_yesterday(self,format="%Y-%m-%d"):
        time = datetime.datetime.now() - datetime.timedelta(days=1)
        return time.strftime(format)

    def get_recentDay(self,day,format="%Y-%m-%d %H:%M:%S"):
        time= datetime.datetime.now()-datetime.timedelta(days=day)
        return time.strftime(format)

    def get_recentMinute(self,mintue,format="%Y-%m-%d %H:%M:%S"):
        time= datetime.datetime.now()-datetime.timedelta(minutes=mintue)
        return time.strftime(format)

    def get_date_by_add_or_minus_day_from_now(self,day,operation,format="%Y-%m-%d %H:%M:%S"):
        if operation=='+':
            time= datetime.datetime.now()+datetime.timedelta(days=day)
        else:
            time= datetime.datetime.now()-datetime.timedelta(days=day)
        return time.strftime(format)

    def timeObjToString(self,obj):
        time_now=time.strftime("%Y-%m-%d %H:%M:%S", obj)

    def get_1st_of_last_month(self,format="%Y-%m-%d %H:%M:%S"):
        today=datetime.datetime.today()
        year=today.year
        month=today.month
        if month==1:
            month=12
            year-=1
        else:
            month-=1
        res=datetime.datetime(year,month,1)
        return res.strftime(format)