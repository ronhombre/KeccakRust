import asia.hombre.neorust.option.PanicFlag

plugins {
    id("asia.hombre.neorust")
}

group = "asia.hombre.keccak"
version = "0.0.7"

repositories {
    mavenCentral()
}

dependencies {
    crate("zeroize:1.8.2") {
        defaultFeatures = false
    }
    crate("hex:0.4.3") {
        optional = true
    }
    devCrate("hex:0.4.3")
    devCrate("criterion:0.8.2")
}

rust {
    authors.add("Ron Lauren Hombre <ronlauren@hombre.asia>")
    edition = "2024"

    library {
        crateType.add("rlib") //We are adding this to avoid double linking when running our binary executables
    }

    features {
        feature("default", "standalone")
        feature("standalone")
        feature("ffi")
        feature("executable", "dep:hex")
    }

    profiles {
        val dev by getting {
            panic = PanicFlag.abort
        }
        val release by getting {
            panic = PanicFlag.abort
        }
    }

    binaries {
        val main by getting {
            noDefaultFeatures = true
            buildFeatures.add("executable")
        }
    }

    tests {
        val main by getting {
            environment.put("RUST_BACKTRACE", "full")
            buildFeatures.add("executable")
        }
    }

    benchmarks {
        val standard by getting {
            buildFeatures.add("executable")
        }
    }
}
