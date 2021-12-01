all: driver/chaos_driver.ko bin/kchaos

driver/chaos_driver.ko:
	$(MAKE) -C ./driver all

bin/kchaos:
	go build -o ./bin/kchaos ./cmd 

clean:
	$(MAKE) -C ./driver clean

.PHONY: all driver/chaos_driver.ko bin/kchaos