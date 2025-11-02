import asia.hombre.neorust.option.BuildProfile

plugins {
    id("asia.hombre.neorust") version "0.4.0"
}

group = "asia.hombre.keccak"
version = "0.0.1"

repositories {
    mavenCentral()
}

dependencies {
    crate("hex:0.4.3")
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

    binaries {
        register("test") {
            //This prints the stacktrace during panic
            environment.put("RUST_BACKTRACE", "1")
        }
        register("test") {
            buildProfile = BuildProfile.RELEASE
        }
    }
}