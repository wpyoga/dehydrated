SPLIT_SCRIPTS = \
	dehydrated-split \
	split-scripts/*.sh \
	main-commands/*.sh \
	util-functions/*.sh \

all: dehydrated-merged

dehydrated-merged: $(SPLIT_SCRIPTS)
	merge-shell.sh dehydrated-split > dehydrated-merged

test: dehydrated-merged
	@diff -u dehydrated dehydrated-merged
	@echo "Test passed"

clean:
	rm -f dehydrated-merged
