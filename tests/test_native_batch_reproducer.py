import hashlib
import io
import os
import tarfile

import pytest

from scripts import run_infrastructure_native_batch as batch


def archive(tmp_path, entries):
    path=tmp_path/'source.tar'
    with tarfile.open(path,'w') as bundle:
        for name,kind,body in entries:
            info=tarfile.TarInfo(name)
            info.type=kind
            info.mode=0o755 if kind==tarfile.DIRTYPE else 0o644
            if kind in {tarfile.SYMTYPE,tarfile.LNKTYPE}:info.linkname='../outside'
            info.size=len(body) if kind==tarfile.REGTYPE else 0
            bundle.addfile(info,io.BytesIO(body) if info.isfile() else None)
    out=tmp_path/'extract';out.mkdir()
    return path,hashlib.sha256(path.read_bytes()).hexdigest(),out


def test_pinned_regular_archive_preserves_exact_source_bytes(tmp_path):
    p,pin,out=archive(tmp_path,[('scripts',tarfile.DIRTYPE,b''),('scripts/test.py',tarfile.REGTYPE,b'print(1)\r\n')])
    report=batch.extract_pinned(p,pin,out)
    assert (out/'scripts/test.py').read_bytes()==b'print(1)\r\n'
    assert report=={'sha256':pin,'entries':2,'uncompressed_bytes':10}


@pytest.mark.parametrize('name',['../outside','/absolute','scripts/../../outside','a\\b','a//b','a/./b','.',
    'bad\nname','C:/outside','x'*4097])
def test_unsafe_paths_are_not_extracted(tmp_path,name):
    p,pin,out=archive(tmp_path,[(name,tarfile.REGTYPE,b'evil')])
    with pytest.raises(batch.BatchUnavailable,match='member_path'):batch.extract_pinned(p,pin,out)
    assert not list(out.iterdir()) and not (tmp_path/'outside').exists()


@pytest.mark.parametrize('kind',[tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.FIFOTYPE,tarfile.CHRTYPE,tarfile.BLKTYPE])
def test_links_and_special_files_are_never_extracted(tmp_path,kind):
    p,pin,out=archive(tmp_path,[('unsafe',kind,b'')])
    with pytest.raises(batch.BatchUnavailable,match='member_type'):batch.extract_pinned(p,pin,out)
    assert not list(out.iterdir())


def test_duplicate_members_are_rejected_instead_of_overwriting(tmp_path):
    p,pin,out=archive(tmp_path,[('same',tarfile.REGTYPE,b'original'),('same',tarfile.REGTYPE,b'new')])
    with pytest.raises(batch.BatchUnavailable,match='member_type'):batch.extract_pinned(p,pin,out)
    assert (out/'same').read_bytes()==b'original'


def test_wrong_pin_rejects_before_any_extract(tmp_path):
    p,_,out=archive(tmp_path,[('file',tarfile.REGTYPE,b'content')])
    with pytest.raises(batch.BatchUnavailable,match='archive_changed'):batch.extract_pinned(p,'0'*64,out)
    assert not list(out.iterdir())


def test_dependency_archive_cannot_supply_source_files(tmp_path):
    p,pin,out=archive(tmp_path,[('scripts/certificate_controller.py',tarfile.REGTYPE,b'evil')])
    with pytest.raises(batch.BatchUnavailable,match='dependency_archive_scope'):
        batch.extract_pinned(p,pin,out,dependencies=True)
    assert not list(out.iterdir())


def test_dependency_regular_package_is_accepted(tmp_path):
    p,pin,out=archive(tmp_path,[('site-packages/pkg.py',tarfile.REGTYPE,b'content')])
    assert batch.extract_pinned(p,pin,out,dependencies=True)['entries']==1


def test_existing_output_is_not_overwritten(tmp_path):
    p,pin,out=archive(tmp_path,[('file',tarfile.REGTYPE,b'content')])
    (out/'existing').write_text('keep')
    with pytest.raises(batch.BatchUnavailable,match='fresh_extract'):batch.extract_pinned(p,pin,out)
    assert (out/'existing').read_text()=='keep'


def test_member_count_bound_is_checked_before_extra_extract(tmp_path,monkeypatch):
    p,pin,out=archive(tmp_path,[('one',tarfile.REGTYPE,b'1'),('two',tarfile.REGTYPE,b'2')])
    monkeypatch.setattr(batch,'MAX_MEMBERS',1)
    with pytest.raises(batch.BatchUnavailable,match='member_type'):batch.extract_pinned(p,pin,out)
    assert (out/'one').read_bytes()==b'1' and not (out/'two').exists()


def test_total_bytes_bound_is_checked_before_extra_extract(tmp_path,monkeypatch):
    p=tmp_path/'compressed.tar.gz'
    with tarfile.open(p,'w:gz') as bundle:
        info=tarfile.TarInfo('expanded');info.size=4096
        bundle.addfile(info,io.BytesIO(b'x'*4096))
    assert p.stat().st_size<512
    out=tmp_path/'extract';out.mkdir()
    monkeypatch.setattr(batch,'MAX_ARCHIVE',512)
    with pytest.raises(batch.BatchUnavailable,match='archive_total_bound'):
        batch.extract_pinned(p,hashlib.sha256(p.read_bytes()).hexdigest(),out)
    assert not list(out.iterdir())


@pytest.mark.parametrize('value',[{},None,{'a':False},{'a':1},{'a':True,'b':False}])
def test_missing_or_non_boolean_cleanup_never_authorizes_snapshot_deletion(value):
    assert batch.cleanup_confirmed(value,('a','b')) is False


def test_only_explicit_all_true_cleanup_confirms_owned_source_removal():
    assert batch.cleanup_confirmed({'a':True,'b':True},('a','b')) is True


@pytest.mark.skipif(os.name!='posix',reason='actual Linux link semantics')
def test_symlink_archive_cannot_follow_external_file(tmp_path):
    p,pin,out=archive(tmp_path,[('file',tarfile.REGTYPE,b'content')])
    link=tmp_path/'linked.tar';link.symlink_to(p)
    with pytest.raises(batch.BatchUnavailable,match='archive_link'):batch.extract_pinned(link,pin,out)


def test_preflight_refuses_non_systemd_or_nonroot_without_output(tmp_path,monkeypatch):
    monkeypatch.setattr(batch.os,'name','nt')
    with pytest.raises(batch.BatchUnavailable,match='owned_linux'):
        batch.execute('missing','0'*64,'missing','0'*64,'0'*64,tmp_path/'output')
    assert not (tmp_path/'output').exists()
