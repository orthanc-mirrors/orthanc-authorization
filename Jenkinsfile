try {
  node('docker') {
    stage 'Retrieve sources'
    deleteDir()
    checkout scm

    lock(resource: 'orthanc-authorization-plugin', inversePrecedence: false) {
      stage 'Build Docker image & run unit tests'
      sh 'scripts/ciBuildDockerImage.sh'
    }
    
    withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-orthanc.osimis.io']]) {
      stage 'Push Docker plugin to AWS'
      sh 'scripts/ciPushToAws.sh ${BRANCH_NAME}'
    }
  }
} 
catch (e) {
    slackSend color: '#FF0000', message: "${env.JOB_NAME} has failed ${env.JOB_URL}"
    throw e
} 