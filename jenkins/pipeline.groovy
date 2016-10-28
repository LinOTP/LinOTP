#!/usr/bin/env groovy

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


/**
 * Return at most n continous chunks of l. If the division is not exact
 * the extra elements will be evenly distributed starting at the
 * beginning.
 * If n exceeds the length of the list only len(l) chunks will be returned.
 *
 * @param l A list. It cannot be empty.
 * @param n The number of chunks to generate. If this number exceeds
 *          len(l) then len(l) chunks of size 1 are generated instead. This number
 *          has to be positive.
 * @return  Chunks (lists) of l
 *
 * For example to divide the list [0, 1, 2, ... 9] into 4 chunks:
 * >>> list(chunk(range(10), 4))
 * [[0, 1, 2], [3, 4, 5], [6, 7], [8, 9]]
 * >>> list(chunk(range(10), 10))
 * [[0], [1], [2], [3], [4], [5], [6], [7], [8], [9]]
 * >>> list(chunk(range(10), 20))
 * [[0], [1], [2], [3], [4], [5], [6], [7], [8], [9]]
 */
ArrayList chunk(ArrayList l, int n) {
    /* Check parameters */
    assert l.size() > 0
    assert n > 0 && n <= l.size()

    int div = l.size().intdiv(n)
    int remainder = l.size() % n
    int i = 0
    def retList = new ArrayList(n)

    for ( int s = 0; s < n; s++ ) {
        if ( remainder > 0 ) {
            retList[s] = l[i..i + div]
            remainder--
            i += (div + 1)
        } else {
            retList[s] = l[i..i + div - 1]
            i += div
        }
    }

    return retList
}


/*
 * Define nodes lists and maps
 */
def buildNodesDeb = ['wolfhound': ['jessie', 'debian-jessie-amd64']]
def buildsUbuntu = ['precise': 'ubuntu-precise-amd64',
                    'trusty': 'ubuntu-trusty-amd64']
                    // 'xenial': 'ubuntu-xenial-amd64']
def buildNodeUbuntu = 'zoe'
def buildNodesPyPI = ['wolfhound']
def installNodesPyPI = ['beggar']
def seleniumHost = 'matisse'
def integrationTestsNodes = ['beggar']


/*
 *         ______________________________________________________________
 *        /XXXXXX/       /        /       /         /         /         /\
 *       /XXXXXX/       /        /       /         /         /         /||\
 *      /XXXXXX/       /        /       /         /         /         /||||\
 *     (      ( Unit  ( Func-  (       ( Publish (         ( Inte-   (||||||)
 *     | Init | Tests | tional | Build | inter-  | Install | gration ||||||||
 *     (      (       ( Tests  (       ( nally   (         ( Tests   (||||||)
 *      \XXXXXX\       \        \       \         \         \         \||||/
 *       \XXXXXX\       \        \       \         \         \         \||/
 *        \XXXXXX\_______\________\_______\_________\_________\_________\/
 *
 */

node('master') {
    stage('Init') {
        /*
         * Checkout LinOTP source
         *
         * Once jenkins bug https://issues.jenkins-ci.org/browse/JENKINS-38046
         * is implemented this can be simplified using a multibranch pipeline.
         */
        try {
            // Try checking out gerrit patchsets
            println "GERRIT_BRANCH: ${GERRIT_BRANCH}"
            println "GERRIT_REFSPEC: ${GERRIT_REFSPEC}"
            checkout([$class: 'GitSCM',
                      branches: [[name: "${GERRIT_BRANCH}"]],
                      browser: [$class: 'GitWeb', repoUrl: 'https://harrison/gitweb?p=LinOTP.git'],
                      doGenerateSubmoduleConfigurations: false,
                      extensions: [[$class: 'CleanCheckout'],
                                   [$class: 'BuildChooserSetting', buildChooser: [$class: 'com.sonyericsson.hudson.plugins.gerrit.trigger.hudsontrigger.GerritTriggerBuildChooser']]],
                      submoduleCfg: [],
                      userRemoteConfigs: [[refspec: "${GERRIT_REFSPEC}", url: 'ssh://jenkins@harrison:29418/LinOTP.git']]
                      ])
        } catch(MissingPropertyException e) {
            // No gerrit variables set. Probably manual build...
            checkout([$class: 'GitSCM',
                      branches: [[name: "${PARAM_GIT_REF}"]],
                      browser: [$class: 'GitWeb', repoUrl: 'https://harrison/gitweb?p=LinOTP.git'],
                      doGenerateSubmoduleConfigurations: false,
                      extensions: [[$class: 'CleanCheckout']],
                      submoduleCfg: [],
                      userRemoteConfigs: [[name: 'origin', refspec: '+refs/*:refs/remotes/origin/*', url: 'ssh://jenkins@harrison:29418/LinOTP.git']]
                      ])
        }
    }

    /*
     * This seems pretty dirty. However, this is the officially recommended way
     * to get the git commit hash (see example in jenkinsci's git repository
     * https://github.com/jenkinsci/pipeline-examples/blob/master/pipeline-examples/gitcommit/gitcommit.groovy).
     */
    sh('git rev-parse HEAD > GIT_COMMIT')
    def GIT_COMMIT = readFile('GIT_COMMIT')

    stash includes: '**', name: 'linotpd', useDefaultExcludes: false

    int NUM_TEST_GROUPS = 4
    int SEED
    if ( PARAM_SEED == '__BUILD_NUMBER__') {
        SEED = env.BUILD_NUMBER.toInteger()
    } else {
        SEED = PARAM_SEED.toInteger()
    }

    println "\n\n++++++++++ Parameters: ++++++++++\n* Commit: ${PARAM_GIT_REF}\n* Seed: ${SEED}\n\n"

    def cwd = pwd()
    def functionalPath = 'linotpd/src/linotp/tests/functional/'
    def functionalSpecialPath = 'linotpd/src/linotp/tests/functional_special/'

    // Assemble list of all test files for functional and functional_special tets
    def functionalList = []
    def functionalSpecialList = []
    def functionalDir = new File(cwd, functionalPath)
    def functionalSpecialDir = new File(cwd, functionalSpecialPath)
    /*
     * Once pipeline bug #26481 is fixed (see https://issues.jenkins-ci.org/browse/JENKINS-26481)
     * the following for loops can be replaced by the following lines. However, at the very moment the
     * closures are executed only once due to the mentioned pipeline bug.
     * This took some time to find out that this is a pipeline bug and not me messing up with groovy :-/
     *
     * functionalDir.eachFileMatch FileType.FILES, ~/test_.*\.py/, {functionalList << it.name}
     * functionalSpecialDir.eachFileMatch FileType.FILES, ~/test_.*\.py/, {functionalSpecialList << it.name}
     */
     /** This snippet is broken by a recent jenkins plugins upgrade (2016-09-12)
    for ( f in functionalDir.listFiles() ) {
        if ( f.name ==~ /test_.*\.py/ ) {
            functionalList << 'linotp/tests/functional/' + f.name
        }
    }
    for ( f in functionalSpecialDir.listFiles() ) {
        if ( f.name ==~ /test_.*\.py/ ) {
            functionalSpecialList << 'linotp/tests/functional_special/' + f.name
        }
    }
    */
    def functionalDirFiles = functionalDir.listFiles()
    for (int i = 0; i < functionalDirFiles.size(); i++) {
        if ( functionalDirFiles[i].name ==~ /test_.*\.py/ ) {
            functionalList << 'linotp/tests/functional/' + functionalDirFiles[i].name
        }
    }
    def functionalSpecialDirFiles = functionalSpecialDir.listFiles()
    for (int i = 0; i < functionalSpecialDirFiles.size(); i++) {
        if ( functionalSpecialDirFiles[i].name ==~ /test_.*\.py/ ) {
            functionalSpecialList << 'linotp/tests/functional_special/' + functionalSpecialDirFiles[i].name
        }
    }


    /*
     * Shuffle functional tests. This is done to ensure that the tests are independent of each other
     * and the order in which they're executed in. The RNG's seed can be set as a build parameter
     * (defaults to the current build number) so that builds can be exactly reproduced.
     */
    Collections.shuffle(functionalList, new Random(SEED))

    def nodes = ['blackeyedpea', 'angelmarie']

    def chunkedList = chunk(functionalList, NUM_TEST_GROUPS)
    for ( int i = 0; i < chunkedList.size(); i++ ) {
        println "test[${i}]: ${chunkedList[i]}"
    }
    println "test[special]: ${functionalSpecialList}"

    // TODO: Can we use the Parallel Test Executor Plugin together with its splitTest construct instead of manually chunking tests?


    /*
     *         ______________________________________________________________
     *        /      /XXXXXXX/        /       /         /         /         /\
     *       /      /XXXXXXX/        /       /         /         /         /||\
     *      /      /XXXXXXX/        /       /         /         /         /||||\
     *     (      ( Unit  ( Func-  (       ( Publish (         ( Inte-   (||||||)
     *     | Init | Tests | tional | Build | inter-  | Install | gration ||||||||
     *     (      (       ( Tests  (       ( nally   (         ( Tests   (||||||)
     *      \      \XXXXXXX\        \       \         \         \         \||||/
     *       \      \XXXXXXX\        \       \         \         \         \||/
     *        \______\XXXXXXX\________\_______\_________\_________\_________\/
     *
     */

    stage('Unit Tests') {
        if (PARAM_RUN_TESTS.toBoolean()) {
            /*
             * Run the unittests on blackeyedpea
             */
            node('blackeyedpea') {
                // Try deleting remaining files
                deleteDir()
                unstash 'linotpd'
                wrap([$class: 'ConfigFileBuildWrapper',
                      managedFiles: [[fileId: 'org.jenkinsci.plugins.managedscripts.ScriptConfig1465200221303', targetLocation: 'unittest.sh']]
                      ]) {
                    try {
                        sh 'sh unittest.sh'
                    } catch (hudson.AbortException e) {
                        // See detailed description in functional tests
                    }
                    step([$class: 'JUnitResultArchiver', testResults: '**/nosetests.xml'])
                    step([$class: 'WarningsPublisher', canResolveRelativePaths: false,
                          defaultEncoding: '', excludePattern: '', healthy: '',
                          includePattern: '', messagesPattern: '',
                          parserConfigurations: [[parserName: 'PyLint', pattern: '**/pylint.log']],
                          thresholdLimit: 'high', unHealthy: '', unstableNewHigh: '1'])
                }
            }
        }
    }


    /*
     *         ______________________________________________________________
     *        /      /       /XXXXXXXX/       /         /         /         /\
     *       /      /       /XXXXXXXX/       /         /         /         /||\
     *      /      /       /XXXXXXXX/       /         /         /         /||||\
     *     (      ( Unit  ( Func-  (       ( Publish (         ( Inte-   (||||||)
     *     | Init | Tests | tional | Build | inter-  | Install | gration ||||||||
     *     (      (       ( Tests  (       ( nally   (         ( Tests   (||||||)
     *      \      \       \XXXXXXXX\       \         \         \         \||||/
     *       \      \       \XXXXXXXX\       \         \         \         \||/
     *        \______\_______\XXXXXXXX\_______\_________\_________\_________\/
     *
     */

    stage('Functional Tests') {
        if (PARAM_RUN_TESTS.toBoolean()) {
            /*
             * Run the functional tests on the machines determined above
             */

            if (!PARAM_WITH_COVERAGE.toBoolean()) {
                /*
                 * This is the default case. Split the LinOTP tests into 5 chunks and
                 * run them in parallel in order to decrease the total test running time.
                 */

                // Create map of nodes
                def nodesMap = [:]
                for ( name in nodes ) {
                    // Create name - closure pairs
                    def subName = ''
                    /*
                     * Once Jenkins bug #26481 (see https://issues.jenkins-ci.org/browse/JENKINS-26481), this should be replaced with
                     * chunkedList.eachWithIndex {list, i ->
                     */
                    for ( int i=0; i < chunkedList.size(); i++ ) {
                        def testChunk = chunkedList[i].join(' ')
                        def innerI = i
                        def innerName = name
                        subName = innerName + "_${i + 1}"
                        nodesMap[subName] = {
                            node(innerName) {
                                // Copy references of outer scope to local variables
                                def localI = innerI
                                def localTestChunk = testChunk
                                def localName = innerName
                                deleteDir()
                                unstash 'linotpd'
                                wrap([$class: 'ConfigFileBuildWrapper',
                                      managedFiles: [[fileId: 'org.jenkinsci.plugins.managedscripts.ScriptConfig1464678927581', targetLocation: 'functional_test.sh']]
                                      ]) {
                                    withEnv(["PARAM_GIT_REF=${PARAM_GIT_REF}",
                                             'PARAM_TEST_TYPE=system',
                                             "PARAM_TEST_NUMBER=${localI + 1}",
                                             'PARAM_RUN_PASTER=false',
                                             "PARAM_WITH_COVERAGE=false",
                                             "PARAM_TEST_LIST=${localTestChunk}"
                                             ]) {
                                        try {
                                            lock("${localName}-functional-venv-${localI + 1}") {
                                                sh 'bash functional_test.sh'
                                            }
                                        } catch (hudson.AbortException e) {
                                            /*
                                             * We need to catch the AbortException because we cannot retrieve the return value of
                                             * the sh command (see jenkins bug https://issues.jenkins-ci.org/browse/JENKINS-26133)
                                             * and the sh command will raise this exception on test failures.
                                             *
                                             * Catching the exception gets us in a bit of a situation: We want to continue the
                                             * build on test failures (i.e. archive the test results) but on the other hand, on
                                             * a manual job abort, we want to quit the job instantly. This can currently only be
                                             * achieved by some groovy exception handling heuristics which would bring several lines
                                             * of boilerplate code into the pipeline (see jenkins bug
                                             * https://issues.jenkins-ci.org/browse/JENKINS-34376).
                                             *
                                             * It seems to me that the solution in jenkins bug #34376 could potentially lead to
                                             * some issues in the future which would be hard to find and resolve. Therefore it
                                             * seems safer to me to catch the AbortException until jenkins bug #26133 is resolved.
                                             * However, if a build is aborted manually during the sh step, the pipeline will
                                             * continue running the following steps (i.e. the JUnitResultArchiver), which should
                                             * usually finish in a few seconds.
                                             */
                                        }
                                    }
                                }
                                step([$class: 'JUnitResultArchiver', testResults: 'linotpd/src/nosetests*.xml'])
                            }
                        }
                    }

                    // Functional special tests
                    def innerName = name
                    subName = innerName + '_special'
                    nodesMap[subName] = {
                        node(innerName) {
                            def localName = innerName
                            deleteDir()
                            unstash 'linotpd'
                            wrap([$class: 'ConfigFileBuildWrapper',
                                  managedFiles: [[fileId: 'org.jenkinsci.plugins.managedscripts.ScriptConfig1464678927581', targetLocation: 'functional_test.sh']]
                                  ]) {
                                withEnv(["PARAM_GIT_REF=${PARAM_GIT_REF}",
                                         'PARAM_TEST_TYPE=system',
                                         'PARAM_TEST_NUMBER=5',
                                         'PARAM_RUN_PASTER=true',
                                         "PARAM_WITH_COVERAGE=false",
                                         "PARAM_TEST_LIST=${functionalSpecialList.join(' ')}"
                                         ]) {
                                    try {
                                        lock("${localName}-functional-venv-5") {
                                            sh 'bash functional_test.sh'
                                        }
                                    } catch (hudson.AbortException e) {
                                        // See detailed comment in functional tests
                                    }
                                }
                            }
                            step([$class: 'JUnitResultArchiver', testResults: 'linotpd/src/nosetests*.xml'])
                        }
                    }
                }

                parallel(nodesMap)
            } else { //PARAM_WITH_COVERAGE
                /*
                 * Run the tests and create a test coverage report
                 * To get a complete report, the tests must run in only one chunk.
                 * This is a much simpler setup than the default one (splitting in 5 chunks)
                 * but leads to drastically longer run times. Therefore this is switched
                 * off by default.
                 */
                node('blackeyedpea') {
                    deleteDir()
                    unstash 'linotpd'
                    wrap([$class: 'ConfigFileBuildWrapper',
                          managedFiles: [[fileId: 'org.jenkinsci.plugins.managedscripts.ScriptConfig1464678927581', targetLocation: 'functional_test.sh']]
                          ]) {
                        withEnv(["PARAM_GIT_REF=${PARAM_GIT_REF}",
                                 'PARAM_TEST_TYPE=system',
                                 'PARAM_TEST_NUMBER=1',
                                 'PARAM_RUN_PASTER=true',
                                 "PARAM_WITH_COVERAGE=true",
                                 "PARAM_TEST_LIST=${(functionalSpecialList + functionalList).join(' ')}"
                                 ]) {
                            try {
                                lock("blackeyedpea-functional-venv-1") {
                                    sh 'bash functional_test.sh'
                                }
                            } catch (hudson.AbortException e) {
                                // See detailed comment in functional tests
                            }
                        }
                    }
                    step([$class: 'JUnitResultArchiver', testResults: 'linotpd/src/nosetests*.xml'])
                    step([$class: 'ArtifactArchiver', artifacts: 'HTML_COVERAGE/**/*', excludes: null])
                }
            }
        } // PARAM_RUN_TESTS
    }


    /*
     *         ______________________________________________________________
     *        /      /       /        /XXXXXXX/         /         /         /\
     *       /      /       /        /XXXXXXX/         /         /         /||\
     *      /      /       /        /XXXXXXX/         /         /         /||||\
     *     (      ( Unit  ( Func-  (       ( Publish (         ( Inte-   (||||||)
     *     | Init | Tests | tional | Build | inter-  | Install | gration ||||||||
     *     (      (       ( Tests  (       ( nally   (         ( Tests   (||||||)
     *      \      \       \        \XXXXXXX\         \         \         \||||/
     *       \      \       \        \XXXXXXX\         \         \         \||/
     *        \______\_______\________\XXXXXXX\_________\_________\_________\/
     *
     */

    stage('Build') {
        /*
         * Build steps
         */
        if (PARAM_RUN_BUILD.toBoolean()) {
            lock('linotp-build-stage') {
                /*
                 * .deb builds
                 */
                def buildNodesMap = [:]

                /*
                 * We would like to write something like 'for (name in buildNodesDeb.keySet())', but, however,
                 * this results in an not serializable exception (jenkins workflow bug
                 * https://issues.jenkins-ci.org/browse/JENKINS-27421). Therefore, we manually convert the set
                 * to an ArrayList…
                 */
                ArrayList buildNodesDebKeys = new ArrayList(buildNodesDeb.keySet())
                for (name in buildNodesDebKeys) {
                    buildNodesMap[name + '_deb'] = {
                        node(name) {
                            def localName = name
                            deleteDir()
                            unstash 'linotpd'
                            wrap([$class: 'ConfigFileBuildWrapper',
                                  managedFiles: [[fileId: 'org.jenkinsci.plugins.managedscripts.ScriptConfig1463756076444', targetLocation: 'build_script.sh']]
                                  ]) {
                                sh 'sh build_script.sh'
                            }
                            step([$class: 'ArtifactArchiver', artifacts: 'RELEASE/**/*', excludes: null, fingerprint: true])
                            // Additionally stash the debs for publishing to avocado
                            stash includes: 'RELEASE/**/*.deb', name: "debs-${buildNodesDeb[localName][0]}"
                        }
                    }
                }

                /*
                 * Ubuntu builds (using pbuilder-dist)
                 */
                ArrayList buildsUbuntuKeys = new ArrayList(buildsUbuntu.keySet())
                for (name in buildsUbuntuKeys) {
                    def innerName = name
                    buildNodesMap[buildNodeUbuntu + '_' + innerName] = {
                        node(buildNodeUbuntu) {
                            def localName = innerName
                            deleteDir()
                            unstash 'linotpd'
                            wrap([$class: 'ConfigFileBuildWrapper',
                                  managedFiles: [[fileId: 'org.jenkinsci.plugins.managedscripts.ScriptConfig1465833346291', targetLocation: 'build_script.sh']]
                                  ]) {
                                lock("${buildNodeUbuntu}-pbuilder") {
                                    sh "sh build_script.sh ${localName}"
                                }
                            }
                            step([$class: 'ArtifactArchiver', artifacts: 'RELEASE/**/*', excludes: null, fingerprint: true])
                            // Additionally stash the debs for publishing to avocado
                            stash includes: 'RELEASE/**/*.deb', name: "debs-${localName}"
                        }
                    }
                }

                /*
                 * PyPI builds
                 */
                for (name in buildNodesPyPI) {
                    buildNodesMap[name + '_pypi'] = {
                        node(name) {
                            deleteDir()
                            unstash 'linotpd'
                            wrap([$class: 'ConfigFileBuildWrapper',
                                  managedFiles: [[fileId: 'org.jenkinsci.plugins.managedscripts.ScriptConfig1466414260758', targetLocation: 'build_script.sh']]
                                  ]) {
                                sh 'sh build_script.sh'
                            }
                            step([$class: 'ArtifactArchiver', artifacts: 'RELEASE/**/*', excludes: null, fingerprint: true])
                            stash includes: 'RELEASE/**/*.tar.gz', name: 'pypi'
                        }
                    }
                }

                parallel(buildNodesMap)
            }
        } // PARAM_RUN_BUILD
    }


    /*
     *         ______________________________________________________________
     *        /      /       /        /       /XXXXXXXXX/         /         /\
     *       /      /       /        /       /XXXXXXXXX/         /         /||\
     *      /      /       /        /       /XXXXXXXXX/         /         /||||\
     *     (      ( Unit  ( Func-  (       ( Publish (         ( Inte-   (||||||)
     *     | Init | Tests | tional | Build | inter-  | Install | gration ||||||||
     *     (      (       ( Tests  (       ( nally   (         ( Tests   (||||||)
     *      \      \       \        \       \XXXXXXXXX\         \         \||||/
     *       \      \       \        \       \XXXXXXXXX\         \         \||/
     *        \______\_______\________\_______\XXXXXXXXX\_________\_________\/
     *
     */

    stage('Publish internally') {
        /*
         * Publishing steps (to avocado)
         */
        if (PARAM_RUN_BUILD.toBoolean() && PARAM_BUILD_PUBLISH.toBoolean()) {
            lock('linotp-publish-stage') {
                def publishNodesMap = [:]

                /*
                 * Publish .deb packages
                 */
                ArrayList buildNodesDebValues = new ArrayList(buildNodesDeb.values())
                for (dist in buildNodesDebValues) {
                    def innerDist = dist
                    publishNodesMap["publish_debs_${dist[0]}"] = {
                        node('avocado') {
                            // Copy references of outer scope to local variables
                            def localDist = innerDist

                            deleteDir()
                            unstash "debs-${dist[0]}"
                            wrap([$class: 'ConfigFileBuildWrapper',
                                  managedFiles: [[fileId: 'org.jenkinsci.plugins.managedscripts.ScriptConfig1466427703881', targetLocation: 'publish_script.sh']]
                                  ]) {
                                sh "sh publish_script.sh ${dist[0]} ${PARAM_GIT_REF} ${dist[1]} ${GIT_COMMIT}"
                            }
                        }
                    }
                }

                /*
                 * Publish ubuntu .deb packages
                 */
                ArrayList pubUbuntuKeys = new ArrayList(buildsUbuntu.keySet())
                for (dist in pubUbuntuKeys) {
                    def innerDist = dist
                    publishNodesMap["publish_debs_${dist}"] = {
                        node('avocado') {
                            // Copy references of outer scope to local variables
                            def localDist = innerDist

                            deleteDir()
                            unstash "debs-${localDist}"
                            wrap([$class: 'ConfigFileBuildWrapper',
                                  managedFiles: [[fileId: 'org.jenkinsci.plugins.managedscripts.ScriptConfig1466427703881', targetLocation: 'publish_script.sh']]
                                  ]) {
                                sh "sh publish_script.sh ${localDist} ${PARAM_GIT_REF} ${buildsUbuntu[localDist]} ${GIT_COMMIT}"
                            }
                        }
                    }
                }

                /*
                 * Publish PyPI packages
                 */
                publishNodesMap['publish_pypi'] = {
                    node('avocado') {
                        deleteDir()
                        unstash 'pypi'
                        wrap([$class: 'ConfigFileBuildWrapper',
                              managedFiles: [[fileId: 'org.jenkinsci.plugins.managedscripts.ScriptConfig1467024509905', targetLocation: 'publish_script.sh']]
                              ]) {
                            sh "sh publish_script.sh"
                        }
                    }
                }

                parallel(publishNodesMap)
            }
        } // PARAM_BUILD_PUBLISH
    }


    /*
     *         ______________________________________________________________
     *        /      /       /        /       /         /XXXXXXXXX/         /\
     *       /      /       /        /       /         /XXXXXXXXX/         /||\
     *      /      /       /        /       /         /XXXXXXXXX/         /||||\
     *     (      ( Unit  ( Func-  (       ( Publish (         ( Inte-   (||||||)
     *     | Init | Tests | tional | Build | inter-  | Install | gration ||||||||
     *     (      (       ( Tests  (       ( nally   (         ( Tests   (||||||)
     *      \      \       \        \       \         \XXXXXXXXX\         \||||/
     *       \      \       \        \       \         \XXXXXXXXX\         \||/
     *        \______\_______\________\_______\_________\XXXXXXXXX\_________\/
     *
     */

    stage('Install') {
        /*
         * Installation steps
         */
        if (PARAM_RUN_BUILD.toBoolean() && PARAM_RUN_INSTALL.toBoolean()) {
            lock('linotp-install-stage') {
                def installNodesMap = [:]
                for (name in installNodesPyPI) {
                    def innerName = name
                    node(innerName) {
                        deleteDir()
                        wrap([$class: 'ConfigFileBuildWrapper',
                              managedFiles: [[fileId: 'org.jenkinsci.plugins.managedscripts.ScriptConfig1467027942512', targetLocation: 'install_script.sh']]
                              ]) {
                            sh "sh install_script.sh"
                        }
                    }
                }

                parallel(installNodesMap)
            }
        } // PARAM_RUN_INSTALL
    }


    /*
     *         ______________________________________________________________
     *        /      /       /        /       /         /         /XXXXXXXXX/\
     *       /      /       /        /       /         /         /XXXXXXXXX/||\
     *      /      /       /        /       /         /         /XXXXXXXXX/||||\
     *     (      ( Unit  ( Func-  (       ( Publish (         ( Inte-   (||||||)
     *     | Init | Tests | tional | Build | inter-  | Install | gration ||||||||
     *     (      (       ( Tests  (       ( nally   (         ( Tests   (||||||)
     *      \      \       \        \       \         \         \XXXXXXXXX\||||/
     *       \      \       \        \       \         \         \XXXXXXXXX\||/
     *        \______\_______\________\_______\_________\_________\XXXXXXXXX\/
     *
     */

    stage('Integration tests') {
        /*
         * Integration tests steps
         */
        if (PARAM_RUN_BUILD.toBoolean() && PARAM_RUN_INSTALL.toBoolean() && PARAM_RUN_TESTS_INTEGRATION.toBoolean()) {
            lock('linotp-integrationtests-stage') {
                def integrationTestsNodesMap = [:]
                for (name in integrationTestsNodes) {
                    def innerName = name
                    node(seleniumHost) {
                        deleteDir()
                        wrap([$class: 'ConfigFileBuildWrapper',
                              managedFiles: [[fileId: 'org.jenkinsci.plugins.managedscripts.ScriptConfig1467031870513', targetLocation: 'integration_test_script.sh']]
                              ]) {
                            try {
                                sh "sh integration_test_script.sh ${innerName}"
                            } catch (hudson.AbortException e) {
                                // See detailed description in functional tests
                            }
                            step([$class: 'JUnitResultArchiver', testResults: '**/nosetests.xml'])
                        }
                    }
                }

                parallel(integrationTestsNodesMap)
            }
        } // PARAM_RUN_TESTS_INTEGRATION
    }

    /*
     * Send mails
     */
    step([$class: 'Mailer', notifyEveryUnstableBuild: true,
          recipients: 'christian.pommranz@lsexperts.de bianca.wellkamp@lsexperts.de alexander.dalloz@lsexperts.de',
          sendToIndividuals: true])
}
