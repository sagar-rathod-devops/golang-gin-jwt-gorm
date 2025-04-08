pipeline{
	agent any
	stages{
		stage('Golang'){
				steps{
					bat 'echo "Running Golang Project"'
                    bat 'echo "Hello from Golang"'
                    bat 'go run main.go'
                    bat 'echo "Golang Project Completed"'
				}
		}
	}
}
