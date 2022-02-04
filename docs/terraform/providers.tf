provider "azurerm" {
  features {}
}

provider "ct" {}

terraform {
  required_providers {
    ct = {
      source  = "poseidon/ct"
      version = "0.9.1"
    }
    azurerm = {
      source = "hashicorp/azurerm"
      version = "2.92.0"
    }
  }
}
