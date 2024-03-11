# P4Lang CNN Model Implementation

## Overview
This project presents a novel approach to executing Convolutional Neural Network (CNN) models directly within network switches, leveraging the P4 programming language. The implementation is based on a 5-layer CNN model, with each layer separately deployed in network switches. This allows for distributed processing of neural network inference directly on the data plane, potentially reducing latency and offloading computation from traditional compute resources.

## Prerequisites
- Familiarity with P4 programming language ([P4Lang documentation](https://p4.org/documentation/))
- Access to P4-capable network switches or a simulation environment (e.g., BMv2)
- Basic understanding of Convolutional Neural Networks

## Installation
1. Clone this repository to your local machine
2. Ensure you have the required P4 development environment set up. Refer to the [P4Lang tutorials repository](https://github.com/p4lang/tutorials) for guidance on setting up your development environment.

## Project Structure
- `switches/`: Contains separate P4 implementations for each of the 5 CNN layers.
- `calc.p4`: Template file where data from each switch is integrated and processed.

## Configuration
To deploy the CNN model across network switches, follow these steps:
1. Implement each CNN layer according to your model's specifications in the `switches/` folder.
2. Replace the placeholder data in `calc.p4` with the actual data from each implemented switch layer.
3. Compile and deploy `calc.p4` to your network switches using your P4 development environment.


## Acknowledgments
This project is inspired by and based on the resources from the [P4Lang tutorials repository](https://github.com/p4lang/tutorials).