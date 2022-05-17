from pulumi_crypto import __version__ as library_version

# The following is automatically updated by semantic-release
_pulumi_crypto_version = '1.0.1'

def test_version():
    assert library_version == _pulumi_crypto_version
