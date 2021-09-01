all: driver/chaos_driver.ko target/release/kchaos

driver/chaos_driver.ko:
	$(MAKE) -C ./driver all

target/debug/kchaos:
	cargo build --debug

target/release/kchaos:
	cargo build --release

clean:
	$(MAKE) -C ./driver clean

.PHONY: all driver/chaos_driver.ko target/release/kchaos target/debug/kchaos