.PHONY: install-libs build-all

current_dir := ${CURDIR}

install-libs:
	@echo  "Installing libs in "$(current_dir)
	mvn install:install-file -Dfile=$(current_dir)/lib/eid-applet-service-signer-jaxb-1.3.jar -DgroupId=be.fedict.eid-applet -DartifactId=eid_applet_service_signer_jaxb -Dversion=1.3 -Dpackaging=jar
	mvn install:install-file -Dfile=$(current_dir)/lib/eid-applet-service-signer-1.3.jar -DgroupId=be.fedict.eid-applet -DartifactId=eid_applet_service_signer -Dversion=1.3 -Dpackaging=jar
	mvn install:install-file -Dfile=$(current_dir)/lib/eid-applet-service-spi-1.3.jar -DgroupId=be.fedict.eid-applet -DartifactId=eid_applet_service_spi -Dversion=1.3 -Dpackaging=jar
	mvn install:install-file -Dfile=$(current_dir)/lib/jacc-1.0.jar -DgroupId=javax.security -DartifactId=jacc -Dversion=1.0 -Dpackaging=jar

	@echo "Done install-libs"

build-all:
	mvn -Dmaven.test.skip=true clean package


