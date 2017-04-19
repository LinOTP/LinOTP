#!/usr/bin/env groovy

/*
 *   LinOTP - the open source solution for two factor authentication
 *   Copyright (C) 2016 KeyIdentity GmbH
 *
 *   This file is part of LinOTP authentication modules.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *    E-mail: linotp@lsexperts.de
 *    Contact: www.linotp.org
 *    Support: www.keyidentity.com
 */

import groovy.io.FileType

/*
 *                              LinOTP Pipeline
 *         ______________________________________________________________
 *        /      /       /        /       /         /         /         /\
 *       /      /       /        /       /         /         /         /||\
 *      /      /       /        /       /         /         /         /||||\
 *     (      ( Unit  ( Func-  (       ( Publish (         ( Inte-   (||||||)
 *     | Init | Tests | tional | Build | inter-  | Install | gration ||||||||
 *     (      (       ( Tests  (       ( nally   (         ( Tests   (||||||)
 *      \      \       \        \       \         \         \         \||||/
 *       \      \       \        \       \         \         \         \||/
 *        \______\_______\________\_______\_________\_________\_________\/
 *
 */


println """++++++++++ Parameters: ++++++++++
           * Commit: ${PARAM_GIT_REF}
           * Docker registry URL: ${PARAM_DOCKER_REGISTRY_URL}
           * Debian mirror: ${PARAM_DEBIAN_MIRROR}
           * Build docker images? ${PARAM_BUILD_DOCKER_IMAGES}
           * Publish docker images? ${PARAM_PUBLISH_DOCKER_IMAGES}
           * Run integration tests? ${PARAM_RUN_TESTS_INTEGRATION}
           * Publish job in Rancher? ${PARAM_PUBLISH_JOB_IN_RANCHER}
           * Rancher URL: ${PARAM_RANCHER_URL}
           """.stripIndent()

/*
 * Image names
 *
 * Currently, the pipeline can be triggered from Gerrit a change, a Gerrit
 * ref change or manually.
 *
 * If a Gerrit ref is supplied, we build images associated with this ref.
 * Otherwise we generate a name based on the
 * branch.
 */


docker_make_args="DEBIAN_MIRROR=${PARAM_DEBIAN_MIRROR}"

try {
    jobname = PARAM_JOBNAME
}
catch(MissingPropertyException) {
    jobname = env.JOB_NAME.replaceAll('/', '-')
}

try {
    println "GERRIT_BRANCH: ${GERRIT_BRANCH}"
    println "GERRIT_CHANGE_NUMBER: ${GERRIT_CHANGE_NUMBER}"
    println "GERRIT_REFSPEC: ${GERRIT_REFSPEC}"
    gerrit_build = true
    build_name = "${jobname}-${GERRIT_BRANCH}-${GERRIT_CHANGE_NUMBER}"
}
catch(MissingPropertyException e) {
    def ref = PARAM_GIT_REF.replaceFirst('heads/','')
    build_name = "${jobname}-${ref}"
    gerrit_build = false
}

docker_image_tag = build_name.replaceAll('/', '-')

println """++ Variables: ++
           * Make args: ${docker_make_args}
           * Job name: ${job_name}
           * Docker / Rancher image tag: ${docker_image_tag}
           * Gerrit build: ${gerrit_build}
           """.stripIndent()

node('master') {
    stage('Init') {
        /*
         * Checkout LinOTP source
         *
         * Once jenkins bug https://issues.jenkins-ci.org/browse/JENKINS-38046
         * is implemented this can be simplified using a multibranch pipeline.
         */

        def parms = [$class: 'GitSCM',
                      branches: [],
                      browser: [$class: 'GitWeb', repoUrl: 'https://harrison/gitweb?p=LinOTP.git'],
                      doGenerateSubmoduleConfigurations: false,
                      extensions: [[$class: 'CleanCheckout']],
                      submoduleCfg: [],
                      userRemoteConfigs: [[
                        url: 'ssh://jenkins@harrison:29418/LinOTP.git']]
                      ]

        if (gerrit_build) {
            // Gerrit change
            parms.branches << [name: "${GERRIT_BRANCH}"]
            parms.extensions << [
                $class: 'BuildChooserSetting',
                buildChooser: [$class: 'com.sonyericsson.hudson.plugins.gerrit.trigger.hudsontrigger.GerritTriggerBuildChooser']
                ]
            parms.userRemoteConfigs[0].refspec = "${GERRIT_REFSPEC}"

        } else {
            // Manual build
            parms.branches << [name: "${PARAM_GIT_REF}"]
            parms.userRemoteConfigs[0].name = 'origin'
            parms.userRemoteConfigs[0].refspec = '+refs/*:refs/remotes/origin/*'
        }

        println "Checkout parameters: ${parms}"
        checkout(parms)

        if (PARAM_DOCKERFY_URL) {
            sh "mkdir -pv build; cd build; wget --no-verbose ${PARAM_DOCKERFY_URL}; chmod ugo+x dockerfy"
        }
        stash includes: '**', name: 'linotpd', useDefaultExcludes: false

    }
}

def doMake(target, timeout_minutes) {
    def make_cmd = "make ${target} ${docker_make_args} DOCKER_TAGS='latest ${docker_image_tag}' LINOTP_IMAGE_TAG=${docker_image_tag} RANCHER_STACK_ID=${docker_image_tag}"

    ansiColor('xterm') {
        timeout(time:timeout_minutes, unit:'MINUTES') {
            sh make_cmd
        }
    }
}

def makeIfParam(condition_name, target, timeout_minutes) {
    /* Run the given make target provided that the parameter is true.
     * We pass the parameter name as a string so that we can log it
     */

    // Get the parameter value from the variable bindings
    def condition_value = params[condition_name]

    if(condition_value) {
        doMake(target, timeout_minutes)
    } else {
        println "${condition_name}=${condition_value} --> skip target ${target}"
    }
}

node('docker') {
    deleteDir()
    unstash 'linotpd'

    stage('Linotp builder') {
        /*
         * Build the linotp builder docker image
         */
        makeIfParam('PARAM_BUILD_DOCKER_IMAGES', 'docker-build-linotp-builder', 5)
    }

    stage('debs') {
        /*
         * Build the linotp debs in the builder image
         */
        makeIfParam('PARAM_BUILD_DOCKER_IMAGES', 'docker-build-debs', 5)
        archiveArtifacts 'build/apt/*'
    }

    stage('Linotp image') {
        /*
         * Build the linotp docker image from the debs
         */
        makeIfParam('PARAM_BUILD_DOCKER_IMAGES', 'docker-build-linotp', 5)
    }

    stage('Build test env') {
        makeIfParam('PARAM_RUN_TESTS_INTEGRATION', 'docker-build-selenium', 5)
    }

    stage('Push images') {
        if(PARAM_PUBLISH_DOCKER_IMAGES) {
            if (!PARAM_BUILD_DOCKER_IMAGES) {
                error("Cannot enable publish docker images without building first (PARAM_BUILD_DOCKER_IMAGES must be set)")
            }

            docker.withRegistry(PARAM_DOCKER_REGISTRY_URL, PARAM_DOCKER_REGISTRY_CREDENTIALS) {
                docker.image("linotp:${docker_image_tag}").push()
            }
        }
    }

    stage('Rancher') {
        if(PARAM_PUBLISH_JOB_IN_RANCHER) {
            if (!PARAM_PUBLISH_DOCKER_IMAGES) {
                error("Cannot enable publish to Rancher without enabling pushing the image")
            }
            withCredentials([usernamePassword(credentialsId: "${PARAM_RANCHER_ACCESS_KEY}",
                                                passwordVariable: 'RANCHER_SECRET_KEY',
                                                usernameVariable: 'RANCHER_ACCESS_KEY')
                            ]) {

               withEnv(["DOCKER_REGISTRY_URL=${PARAM_DOCKER_REGISTRY_URL}"]) {
                  withEnv(["RANCHER_URL=${PARAM_RANCHER_URL}"]) {
                        doMake('rancher-linotp-create', 2)
                        makeIfParam('PARAM_START_JOB_IN_RANCHER', 'rancher-linotp-up', 2)
                  }
               }
            }
        }
    }

    stage('Selenium tests') {
        /*
         * Run the Selenium unit tests in a docker compose environment
         */
        makeIfParam('PARAM_RUN_TESTS_INTEGRATION', 'docker-run-selenium', 60)
    }
}
