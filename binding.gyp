{
    "targets": [{
        "target_name": "signun",
        "actions": [
            {
                # For debugging purposes, it's printed whether we
                # are building with GMP or not.
                'action_name': 'print_gmp_found',
                'action': [ 'echo', 'Building with GMP: <(gmp_found)' ],
                'inputs': [],
                # Must reference a source file here so that
                # the action is called.
                'outputs': [ "./src/native/src/signun.c" ]
            }
        ],
        "variables": {
            "conditions": [
                [
                    "OS=='win'",
                    # On Windows, we don't even try to find GMP.
                    {
                        "gmp_found%": "false"
                    },
                    # Otherwise, check if it's installed.
                    {
                        "gmp_found%": "<!(sh ./util/has_lib.sh gmp)"
                    }
                ]
            ]
        },
        "sources": [
            # Dependencies
            # blake2
            "./dependencies/BLAKE2/sse/blake2b.c",

            # secp256k1
            "./dependencies/secp256k1/src/secp256k1.c",

            # signun
            "./src/native/src/signun.c",
            "./src/native/src/signun_node.c",
            "./src/native/src/signun_util.c",
            "./src/native/src/secp256k1_addon/addon.c",
            "./src/native/src/secp256k1_addon/private_key_verify.c",
            "./src/native/src/secp256k1_addon/public_key_create.c",
            "./src/native/src/secp256k1_addon/sign.c",
            "./src/native/src/secp256k1_addon/verify.c"
        ],
        "include_dirs": [
            # Dependencies
            # Local Headers (including GMP)
            "/usr/local/include",

            # blake2
            "./dependencies/BLAKE2/sse",

            # secp256k1
            "./dependencies/secp256k1",
            "./dependencies/secp256k1/include",
            "./dependencies/secp256k1/src",

            # signun
            "./src/native/include"
        ],
        "defines": [
            "ENABLE_MODULE_RECOVERY=1"
        ],
        "cflags": [
            "-Wall",
            "-Wextra",
            "-Werror",

            # These warnings should be ignored, because they're
            # inherently present in secp256k1.
            "-Wno-maybe-uninitialized",
            "-Wno-uninitialized",
            "-Wno-unused-function"
        ],
        "conditions": [
            [
                "gmp_found == 'true'",
                # If GMP is installed and found.
                {
                    "defines": [
                        # GMP is installed on the system.
                        "HAVE_LIBGMP=1",
                        # Use GMP-based implementation for num.
                        "USE_NUM_GMP=1",
                        # Use the num-based field inverse implementation.
                        "USE_FIELD_INV_NUM=1",
                        # Use the num-based scalar inverse implementation.
                        "USE_SCALAR_INV_NUM=1"
                    ],
                    "libraries": [
                        "-lgmp"
                    ]
                },
                # Otherwise.
                {
                    "defines": [
                        # Use no num implementation.
                        "USE_NUM_NONE=1",
                        # Use the native field inverse implementation.
                        "USE_FIELD_INV_BUILTIN=1",
                        # Use the native scalar inverse implementation.
                        "USE_SCALAR_INV_BUILTIN=1"
                    ]
                }
            ],
            [
                "target_arch=='x64'",
                # 64-bit architecture
                {
                    # On 64-bit, we always have SSE2, however
                    # MSVC fails to provide the __SSE2__ define.
                    "defines": [
                        "__SSE2__=1"
                    ]
                }
            ],
            [
                "target_arch=='x64' and OS!='win'",
                # 64-bit architecture but NOT Windows.
                {
                    "defines": [
                        # __int128 is available and supported.
                        "HAVE___INT128=1",
                        # Enable x86_64 assembly optimizations.
                        "USE_ASM_X86_64=1",
                        # Use the FIELD_5X52 field implementation.
                        "USE_FIELD_5X52=1",
                        # TODO Not sure if needed.
                        "USE_FIELD_5X52_INT128=1",
                        # Use the 4x64 scalar implementation.
                        "USE_SCALAR_4X64=1"
                    ]
                },
                # Otherwise.
                {
                    "defines": [
                        # Use the FIELD_10X26 field implementation.
                        "USE_FIELD_10X26=1",
                        # Use the 8x32 scalar implementation.
                        "USE_SCALAR_8X32=1"
                    ]
                }
            ],
            [
                "OS=='mac'", {
                # On Mac.
                    "libraries": [
                        "-L/usr/local/lib"
                    ],
                }
            ]
        ]
    }]
}
