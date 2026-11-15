"""A prospective selector must not shrink or relabel its population later."""

from copy import deepcopy

import pytest

from scripts.run_audit_member_transfer import validate_raw


def packet():
    selected = {'raw_member':'sample/gather/host/logs/auth.log',
                'label_member':'sample/labels/host/logs/auth.log',
                'facts_member':'sample/gather/host/facts.json',
                'kind':'auth','raw_bytes':100,'label_bytes':20}
    spec = {'archive_sha256':'a'*64,'simulation_start':1,'simulation_end':3,'selected':[selected]}
    audit = {'completed':True,'candidate_freeze_sha256':'b'*64,'archive_sha256':'a'*64,
             'label_bodies_opened':0,'population':2,'pairs':[{'raw_rows':2,'provenance':{
                 **selected,'simulation_start':1,'simulation_end':3,'archive_sha256':'a'*64,
                 'source_timezone':'UTC','label_body_opened':False}}]}
    return audit,spec


def test_metadata_selected_population_is_maintained_in_the_raw_packet():
    audit,spec = packet()
    validate_raw(audit,spec,'b'*64)


@pytest.mark.parametrize('change',['dropped_pair','extra_pair','source_hash','freeze_hash','label_opened',
                                   'population','row_zero','row_bool','row_bound','timezone','simulation_bounds',
                                   'member_name','different_label','kind','different_size'])
def test_unpaired_or_postfreeze_population_changes_cannot_be_scored(change):
    audit,spec = packet()
    provenance = audit['pairs'][0]['provenance']
    if change == 'dropped_pair':audit['pairs'] = []
    elif change == 'extra_pair':audit['pairs'].append(deepcopy(audit['pairs'][0]))
    elif change == 'source_hash':audit['archive_sha256'] = 'c'*64
    elif change == 'freeze_hash':audit['candidate_freeze_sha256'] = 'c'*64
    elif change == 'label_opened':audit['label_bodies_opened'] = 1
    elif change == 'population':audit['population'] = 1
    elif change == 'row_zero':audit['pairs'][0]['raw_rows'] = 0
    elif change == 'row_bool':audit['pairs'][0]['raw_rows'] = True
    elif change == 'row_bound':audit['pairs'][0]['raw_rows'] = 100001
    elif change == 'timezone':provenance['source_timezone'] = 'local'
    elif change == 'simulation_bounds':provenance['simulation_end'] = 4
    elif change == 'member_name':provenance['raw_member'] = 'sample/gather/other/logs/auth.log'
    elif change == 'different_label':provenance['label_member'] = 'sample/labels/other/logs/auth.log'
    elif change == 'kind':provenance['kind'] = 'normal'
    else:provenance['raw_bytes'] = 99
    with pytest.raises(ValueError,match='audit_transfer_'):
        validate_raw(audit,spec,'b'*64)
