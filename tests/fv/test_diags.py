import sh


def test_diags():
    calicoctl = sh.sudo.bake("dist/calicoctl")
    link = calicoctl("diags")
    assert "https://transfer.sh/" in link
