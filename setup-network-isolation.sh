#!/bin/bash
# setup-network-isolation.sh
# This script sets up network isolation for Docker Swarm services

set -e

# Function to create an isolated overlay network for an organization
create_org_network() {
    local org_id="$1"
    local network_name="org_${org_id}_overlay"
    
    # Check if network already exists
    if docker network ls | grep -q "$network_name"; then
        echo "Network $network_name already exists"
    else
        echo "Creating isolated network $network_name for organization $org_id"
        
        # Create an internal overlay network with encryption
        docker network create \
            --driver overlay \
            --attachable \
            --internal \
            --opt encrypted=true \
            --subnet "10.${org_id}.0.0/16" \
            "$network_name"
        
        echo "Network $network_name created successfully"
    fi
}

# Function to apply network policies to running services
apply_network_policies() {
    local org_id="$1"
    local network_name="org_${org_id}_overlay"
    
    echo "Applying network policies for organization $org_id"
    
    # Get all services in the organization
    services=$(docker service ls --filter label=com.koompi.org.id=$org_id -q)
    
    for service_id in $services; do
        service_name=$(docker service inspect --format '{{.Spec.Name}}' "$service_id")
        echo "Applying network policies to service $service_name"
        
        # Update service with network isolation labels if they don't exist
        if ! docker service inspect "$service_id" | grep -q "com.koompi.network.isolation"; then
            docker service update \
                --label-add "com.koompi.network.isolation=true" \
                --label-add "com.koompi.network.allowInternal=true" \
                --label-add "com.koompi.network.allowExternal=false" \
                "$service_id"
        fi
    done
}

# Function to create default policy to block cross-organization traffic
setup_swarm_firewall() {
    echo "Setting up Swarm firewall on manager nodes"
    
    # Run on each manager node
    docker node ls --filter role=manager -q | xargs -I{} \
        docker node update --label-add org.koompi.network.firewall=enabled {}
    
    # Create a service that runs on manager nodes to set up iptables rules
    docker service create \
        --name network-firewall \
        --mode global \
        --constraint 'node.role==manager' \
        --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock \
        --mount type=bind,src=/var/lib/docker/,dst=/var/lib/docker/ \
        --cap-add NET_ADMIN \
        --cap-add SYS_ADMIN \
        192.168.1.109:80/libary/alpine-dind \
        /bin/sh -c '
            apk add --no-cache iptables
            
            # Set up iptables rules to isolate traffic between organization networks
            iptables -A FORWARD -i docker_gwbridge -o docker_gwbridge -j ACCEPT
            
            # Block inter-organization traffic
            for network in $(docker network ls --filter driver=overlay --format "{{.Name}}"); do
                if [[ $network == org_*_overlay ]]; then
                    org_id=$(echo $network | sed "s/org_\(.*\)_overlay/\1/")
                    
                    # Get the subnet for this org network
                    subnet=$(docker network inspect $network --format "{{range .IPAM.Config}}{{.Subnet}}{{end}}")
                    
                    # Block traffic from other org networks to this one
                    for other_network in $(docker network ls --filter driver=overlay --format "{{.Name}}"); do
                        if [[ $other_network == org_*_overlay && $other_network != $network ]]; then
                            other_subnet=$(docker network inspect $other_network --format "{{range .IPAM.Config}}{{.Subnet}}{{end}}")
                            
                            # Block traffic between different org networks
                            iptables -A FORWARD -s $other_subnet -d $subnet -j DROP
                        fi
                    done
                fi
            done
            
            # Keep container running to maintain iptables rules
            while true; do sleep 3600; done
        '
}

# Main execution
echo "Setting up network isolation for Docker Swarm"

# Create or ensure proxy network exists
if ! docker network ls | grep -q "proxy-network"; then
    echo "Creating proxy-network"
    docker network create --driver overlay proxy-network
fi

# Process all organizations
echo "Processing all organizations..."
orgs=$(docker service ls --format '{{.Labels}}' | grep -o 'com.koompi.org.id=[^ ]*' | cut -d= -f2 | sort -u)

for org_id in $orgs; do
    echo "Processing organization: $org_id"
    create_org_network "$org_id"
    apply_network_policies "$org_id"
done

# Setup firewall for cross-organization traffic isolation
setup_swarm_firewall

echo "Network isolation setup complete"
