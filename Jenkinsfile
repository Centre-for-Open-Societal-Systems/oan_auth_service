// Jenkins job type: "Pipeline" (or "Multibranch Pipeline" filtered to develop),
// "Pipeline script from SCM" pointing at this repo, with:
//   Additional Behaviours -> Custom workspace ->
//     /home/ubuntu/oan_grievance_stack/development/frappe-bench/apps/oan_auth_service
// so Jenkins' checkout lands directly in the bind-mounted bench apps/ path
// the running oan_grievance-frappe-1 container actually uses.
pipeline {
    agent { label 'oan-grievance-box-a' }

    options {
        disableConcurrentBuilds()
        timestamps()
    }

    triggers {
        githubPush()
    }

    environment {
        BENCH_DIR = '/home/ubuntu/oan_grievance_stack/development/frappe-bench'
        CONTAINER = 'oan_grievance-frappe-1'
        SITE      = 'grievance.localhost'
        APP       = 'oan_auth_service'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install python deps') {
            steps {
                sh """
                    docker exec ${CONTAINER} bash -lc "cd ${BENCH_DIR} && ./env/bin/pip install -e apps/${APP}"
                """
            }
        }

        stage('Migrate') {
            steps {
                sh """
                    docker exec ${CONTAINER} bash -lc "cd ${BENCH_DIR} && bench --site ${SITE} migrate"
                """
            }
        }

        stage('Build assets') {
            steps {
                sh """
                    docker exec ${CONTAINER} bash -lc "cd ${BENCH_DIR} && bench build --app ${APP}"
                """
            }
        }

        stage('Restart bench') {
            steps {
                sh "docker restart ${CONTAINER}"
                sh 'sleep 8'
            }
        }

        stage('Smoke test') {
            steps {
                sh 'curl -fsSI http://127.0.0.1:8100/'
            }
        }
    }

    post {
        success {
            echo "${env.APP} deployed: ${env.GIT_COMMIT ?: 'unknown commit'}"
        }
        failure {
            echo """
                Deploy failed. Since this app shares oan_grievance-frappe-1
                with oan_grievance_service, check whether oan_grievance_service
                needs its own redeploy against this new auth version before
                retrying.
            """
        }
    }
}