import asia.hombre.neorust.option.BuildProfile
import asia.hombre.neorust.task.CargoBuild

plugins {
    id("asia.hombre.neorust") version "0.5.4"
}

group = "asia.hombre.keccak"
version = "0.0.6"

repositories {
    mavenCentral()
}

dependencies {
    crate("hex:0.4.3") {
        optional = true
    }
    devCrate("hex:0.4.3")
}

rust {
    manifest {
        packaging {
            name = "keccakrust"
            authors.add("Ron Lauren Hombre <ronlauren@hombre.asia>")
            edition = "2024"
        }
        lib {
            crateType.add("dylib")
            crateType.add("rlib") //We are adding this to avoid double linking when running our binary executables
        }
    }

    features {
        feature("default", listOf("standalone"))
        feature("standalone")
        feature("executable", listOf("dep:hex"))
    }

    profiles {
        dev.put("panic", "abort")
        release.put("panic", "abort")
    }

    binaries {
        register("test") {
            //This prints the stacktrace during panic
            environment.put("RUST_BACKTRACE", "full")
            arguments.addAll(listOf("--features", "executable"))
        }
        register("test") {
            buildProfile = BuildProfile.RELEASE
        }
    }
}

//Configure it afterEvaluate since that's when the tasks are added
afterEvaluate {
    tasks.findByName("buildTest")!!.apply { this as CargoBuild
        features.set("executable")
        noDefaultFeatures = true
    }
}