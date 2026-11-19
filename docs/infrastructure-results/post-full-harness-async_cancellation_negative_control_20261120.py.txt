"""Deliberately make source I/O synchronous; the cancellation test must reject it."""
import hashlib
import json
import os
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

source=Path(sys.argv[1]).resolve()
output=Path(sys.argv[2]).resolve()
output.mkdir(parents=True,exist_ok=False)
os.chdir(source)
sys.path.insert(0,str(source))
os.environ['AWS_EC2_METADATA_DISABLED']='true'
import pytest
from app.services import session_analysis_evidence as evidence

async def synchronous(function,*args,**kwargs):
    return function(*args,**kwargs)

before=hashlib.sha256((source/'app/services/session_analysis_evidence.py').read_bytes()).hexdigest()
evidence.settled_io=synchronous
code=pytest.main(['-q','tests/test_async_evidence_io.py::test_cancelled_sdk_source_check_settles_without_blocking_event_loop[adapter_retry]',f'--junitxml={output}/negative-control.xml'])
suite=ET.parse(output/'negative-control.xml').getroot().find('testsuite')
result={'schema':'owned-async-test-negative-control-1','source_commit':'8d2df526843418e50124b23808c54b9597e79008','expected_pytest_exit_code':1,'actual_pytest_exit_code':int(code),'tests':int(suite.get('tests')),'failures':int(suite.get('failures')),'errors':int(suite.get('errors')),'in_memory_mutation':'replace settled_io with synchronous source callback','source_file_unchanged':before==hashlib.sha256((source/'app/services/session_analysis_evidence.py').read_bytes()).hexdigest(),'paid_api_calls':0,'control_rejected':int(code)==1 and suite.get('failures')=='1' and suite.get('errors')=='0'}
(output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
raise SystemExit(0 if result['control_rejected'] and result['source_file_unchanged'] else 1)
