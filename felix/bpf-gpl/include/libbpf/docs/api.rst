.. SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

.. _api:

.. toctree:: Table of Contents


LIBBPF API
==========

Error Handling
--------------

When libbpf is used in "libbpf 1.0 mode", API functions can return errors in one of two ways.

You can set "libbpf 1.0" mode with the following line:

.. code-block::

    libbpf_set_strict_mode(LIBBPF_STRICT_DIRECT_ERRS | LIBBPF_STRICT_CLEAN_PTRS);

If the function returns an error code directly, it uses 0 to indicate success
and a negative error code to indicate what caused the error. In this case the
error code should be checked directly from the return, you do not need to check
errno.

For example:

.. code-block::

    err = some_libbpf_api_with_error_return(...);
    if (err < 0) {
        /* Handle error accordingly */
    }

If the function returns a pointer, it will return NULL to indicate there was
an error. In this case errno should be checked for the error code.

For example:

.. code-block::

    ptr = some_libbpf_api_returning_ptr();
    if (!ptr) {
        /* note no minus sign for EINVAL and E2BIG below */
        if (errno == EINVAL) {
           /* handle EINVAL error */
        } else if (errno == E2BIG) {
           /* handle E2BIG error */
        }
    }

libbpf.h
--------
.. doxygenfile:: libbpf.h
   :project: libbpf
   :sections: func define public-type enum

bpf.h
-----
.. doxygenfile:: bpf.h
   :project: libbpf
   :sections: func define public-type enum

btf.h
-----
.. doxygenfile:: btf.h
   :project: libbpf
   :sections: func define public-type enum

xsk.h
-----
.. doxygenfile:: xsk.h
   :project: libbpf
   :sections: func define public-type enum

bpf_tracing.h
-------------
.. doxygenfile:: bpf_tracing.h
   :project: libbpf
   :sections: func define public-type enum

bpf_core_read.h
---------------
.. doxygenfile:: bpf_core_read.h
   :project: libbpf
   :sections: func define public-type enum

bpf_endian.h
------------
.. doxygenfile:: bpf_endian.h
   :project: libbpf
   :sections: func define public-type enum
