from XRootD import client
import pytest, sys

def test_creation():
    u = client.Client("root://localhost").url
    assert u is not None

def test_deletion():
    u = client.Client("root://localhost").url
    del u
    
    if sys.hexversion > 0x02050000:
        pytest.raises(UnboundLocalError, 'assert u')
    else:
        pytest.raises(NameError, 'assert u')

def test_getters():
    u = client.Client("root://user1:passwd1@host1:123//path?param1=val1&param2=val2").url
    assert u.IsValid()
    print u.GetHostId()
    assert u.GetHostId() == 'user1@host1:123'
    assert u.GetProtocol() == 'root'
    assert u.GetUserName() == 'user1'
    assert u.GetPassword() == 'passwd1'
    assert u.GetHostName() == 'host1'
    assert u.GetPort() == 123
    assert u.GetPath() == '/path'
    assert u.GetPathWithParams() == '/path?param1=val1&param2=val2'

def test_setters():
    u = client.Client('root://localhost').url
    u.SetProtocol('root')
    assert u.GetProtocol() == 'root'
    u.SetUserName('user1')
    assert u.GetUserName() == 'user1'
    u.SetPassword('passwd1')
    assert u.GetPassword() == 'passwd1'
    u.SetHostName('host1')
    assert u.GetHostName() == 'host1'
    u.SetPort(123)
    assert u.GetPort() == 123
    u.SetPath('/path')
    assert u.GetPath() == '/path'
    u.Clear()
    assert str(u) == ''
