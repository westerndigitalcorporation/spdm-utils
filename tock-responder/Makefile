# Make uses /bin/sh by default, which is a different shell on different OSes.
# Specify Bash instead so we don't have to test against a variety of shells.
include libtock-rs/Makefile

# Creates the `make <BOARD> EXAMPLE=<EXAMPLE>` targets. Arguments:
#  1) The name of the platform to build for.
#  2) The target architecture the platform uses.
#
# A different --target-dir is passed for each platform to prevent race
# conditions between concurrent cargo run invocations. See
# https://github.com/tock/libtock-rs/issues/366 for more information.
define spdm_build
.PHONY: $(1)_spdm_responder
$(1)_spdm_responder: toolchain
	LIBTOCK_PLATFORM=$(1) cargo run $(features) \
		$(release) --target=$(2) --target-dir=target/$(1)
	mkdir -p target/tbf/$(1)
	cp target/$(1)/$(2)/release/spdm-tock-responder.{tab,tbf} \
		target/tbf/$(1)
endef

$(eval $(call spdm_build,apollo3,thumbv7em-none-eabi))
$(eval $(call spdm_build,esp32_c3_devkitm_1,riscv32imc-unknown-none-elf))
$(eval $(call spdm_build,hail,thumbv7em-none-eabi))
$(eval $(call spdm_build,imix,thumbv7em-none-eabi))
$(eval $(call spdm_build,microbit_v2,thumbv7em-none-eabi))
$(eval $(call spdm_build,nucleo_f429zi,thumbv7em-none-eabi))
$(eval $(call spdm_build,nucleo_f446re,thumbv7em-none-eabi))
$(eval $(call spdm_build,nrf52840,thumbv7em-none-eabi))
$(eval $(call spdm_build,raspberry_pi_pico,thumbv6m-none-eabi))
$(eval $(call spdm_build,nano_rp2040_connect,thumbv6m-none-eabi))
$(eval $(call spdm_build,stm32f3discovery,thumbv7em-none-eabi))
$(eval $(call spdm_build,stm32f412gdiscovery,thumbv7em-none-eabi))
$(eval $(call spdm_build,opentitan,riscv32imc-unknown-none-elf))
$(eval $(call spdm_build,hifive1,riscv32imac-unknown-none-elf))
$(eval $(call spdm_build,nrf52,thumbv7em-none-eabi))
$(eval $(call spdm_build,imxrt1050,thumbv7em-none-eabi))
$(eval $(call spdm_build,msp432,thumbv7em-none-eabi))
$(eval $(call spdm_build,clue_nrf52840,thumbv7em-none-eabi))

.PHONY: clean
clean:
		cargo clean
		rm -rf target