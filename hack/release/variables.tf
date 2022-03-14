variable "google_project" {
  type = string
}
variable "google_region" {
  type = string
}
variable "google_zone" {
  type = string
}
variable "prefix" {
  type = string
}

variable "machine_type" {
  type    = string
  default = "n2-standard-32"
}

variable "disk_size" {
  type    = number
  default = 100
}

variable "disk_type" {
  type    = string
  default = "pd-ssd"
}

variable "image" {
  type        = string
  description = "Select which image family to use."
  default     = "ubuntu-1804-lts"
}

variable "google_network" {
  type        = string
  default     = "default"
  description = "The name of the network to bring instances up on."
}

variable "github_token" {
  type        = string
}

variable "gcr_auth_path" {
  type        = string
  description = "Path to docker authentication file for GCR."
  validation {
    condition     = fileexists(pathexpand(var.gcr_auth_path))
    error_message = "Invalid docker auth file."
  }
}

variable "dockerhub_token" {
  type        = string
}

variable "dockerhub_user" {
  type        = string
}

variable "quay_token" {
  type        = string
}

variable "quay_user" {
  type        = string
}
