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

variable "gcr_auth_path" {
  type        = string
  description = "Path to docker authentication file. Needed to publish images to dockerhub, quay, and GCR."
  validation {
    condition     = fileexists(pathexpand(var.gcr_auth_path))
    error_message = "Invalid docker auth file."
  }
}

variable "github_token" {
  type        = string
  validation {
    condition     = var.github_token != ""
    error_message = "Must specify a Github token."
  }
}
