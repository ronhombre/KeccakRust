plugins {
    id("asia.hombre.neorust") version "0.4.0"
}

group = "asia.hombre.keccak"
version = "0.0.1"

repositories {
    mavenCentral()
}

dependencies {
    //TODO: Add crates here
}

rust {
    manifest {
        packaging {
            name = "keccak-rust"
            authors.add("Ron Lauren Hombre <ronlauren@hombre.asia>")
            edition = "2024"
        }
        lib {
            crateType.add("dylib")
        }
    }

    binaries {
        register("test")
    }
}