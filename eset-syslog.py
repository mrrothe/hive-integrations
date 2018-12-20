import re
import json
import datetime
import socketserver
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CustomFieldHelper

import hive_config

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = bytes.decode(self.request[0].strip())
        #socket = self.request[1]
        pat=re.compile("(?P<syslog_date>\w{3}\s+\d{1,2}\s\d\d:\d\d:\d\d)\s(?P<eraserver>\S+)\sERA\s*Server.+{\"event_type\":\"(?P<event>[^\"]*)\",\"(?:ipv4\":\"(?P<src_ip>[^\"]*)\",\")?(?:hostname\":\"(?P<device>[^\"]*)\",\")?(?:ipv6\":\"(?P<src_ipv6>[^\"]*)\",\")?source_uuid\":\"(?P<src_uid>[^\"]*)\",\"occured\":\"(?P<date>[^\"]*)\",\"severity\":\".*?\",\"threat_type\":\"(?P<threattype>(suspicious|potentially unsafe|potentially unwanted) application|worm|trojan|application|potentially unwanted application)\",\"threat_name\":\"(?P<threat_name>[^\"]*)\",\"(?:threat_flags\":\"(?P<threat_flags>[^\"]*)\",\")?scanner_id\":\"(?P<scanner_id>[^\"]*)\",\"scan_id\":\"(?P<scan_id>[^\"]*)\",\"engine_version\":\"(?P<engine_version>[^\"]*)\",\"object_type\":\"(?P<object_type>[^\"]*)\",\"object_uri\":\"(?:file:/*)?(?P<filename>[^\"]*)\",\"(?:action_taken\":\"(?P<action_taken>[^\"]*)\",\")?(?:action_error\":\"(?P<action_error>[^\"]*)\",\")?threat_handled\":(?P<threat_handled>[^,]*),\"need_restart\":(?P<need_restart>true|false)(?:,\"firstseen\":\"(?P<first_seen>[^\"]*)\")?(?:,\"username\":\"(?:(?P<domain>[^\\\"]+)\\\\)?(?P<username>[^\"]*)\")?(?:,\"processname\":\"(?P<process_name>[^\"]*)\")?(?:,\"circumstances\":\"(?P<circumstances>[^\"]*)\")?(?:,\"firstseen\":\"(?P<firstseen>[^\"]*)\")?(?:,\"hash\":\"(?P<hash>[^\"]*)\")?}")
        r1=pat.match(data)
        newcase(r1)

def newcase(casedata):
    api = TheHiveApi('http://'+hive_config.url+':'+hive_config.port, hive_config.apikey)
    customFields = CustomFieldHelper().add_string('customer', hive_config.customer).build()
    case = Case(title='mal-'+datetime.date.today().isoformat(),
            tags=['ESET', casedata.group('threattype')],
            customFields=customFields,
            template="ESET Threat Detected")
    id = None
    response = api.create_case(case)
    if response.status_code == 201:
        print(json.dumps(response.json(), indent=4, sort_keys=True))
        print('')
        id = response.json()['id']
    else:
        print('ko: {}/{}'.format(response.status_code, response.text))
        sys.exit(0)

    response = api.get_case(id)
    if response.status_code == requests.codes.ok:
        print(json.dumps(response.json(), indent=4, sort_keys=True))
        print('')
    else:
        print('ko: {}/{}'.format(response.status_code, response.text))

    domain = CaseObservable(dataType='hash',
                            data=casedata.group('hash'),
                            tlp=1,
                            ioc=True,
                            tags=['ESET'],
                            message='File hash identified by ESET Security'
                            )
    response = api.create_case_observable(id, domain)
    if response.status_code == 201:
        print(json.dumps(response.json(), indent=4, sort_keys=True))
        print('')
    else:
        #print('ko: {}/{}'.format(response.status_code, response.text))
        sys.exit(0)

if __name__ == "__main__":
    try:
        server = socketserver.UDPServer(("0.0.0.0",1514), SyslogUDPHandler)
        server.serve_forever(poll_interval=1)
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        print(" Done")