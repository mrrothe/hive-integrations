
import hive_config 
import requests
import sys
import json
import time
import datetime
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CustomFieldHelper

def newcase(args):
    api = TheHiveApi('http://'+hive_config.url+':'+hive_config.port, hive_config.apikey)
    avlink="https://10.201.1.100/ossim/#analysis/alarms/alarms-" + args.alarmhash #Generate AV alarm link # Makle URL generic
    customFields = CustomFieldHelper().add_string('customer', hive_config.customer).build()
    case = Case(title='usm-'+datetime.date.today().isoformat(),
            tags=['USM', 'Attack'], # Do something clever here with alienvault plugin category
            customFields=customFields,
            template="USM")
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

    domain = CaseObservable(dataType='filename',
                            data=['pic.png'],
                            tlp=1,
                            ioc=True,
                            tags=['thehive4py'],
                            message='test'
                            )
    response = api.create_case_observable(id, domain)
    if response.status_code == 201:
        print(json.dumps(response.json(), indent=4, sort_keys=True))
        print('')
    else:
        print('ko: {}/{}'.format(response.status_code, response.text))
        sys.exit(0)




    # 'client': pd_config.customer,
    # 'payload': {
    #     'summary': args.details,
    #     'severity': pd_risk,
    #     'source': pd_config.customer,
    #     "custom_details": {
    #         'src': args.src,
    #         'src_whois': args.whois_src,
    #         'dst': args.dst,
    #         'dst_whois': args.whois_dst,
    #         'raw_log': args.desc,
    #     }
    # }




