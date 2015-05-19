import sh

calicoctl = sh.sudo.bake("dist/calicoctl")
link = calicoctl("diags")
if "https://transfer.sh/" in link:
    pass
else:
    raise
