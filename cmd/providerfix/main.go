package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type provider struct {
	Nickname    string `bson:"nickname"`
	HostAddress string `bson:"host_address"`
	Port        int    `bson:"port"`
	ProvideIOS  bool   `bson:"provide_ios"`
}

func main() {
	mongoAddr := flag.String("mongo", "mongodb://localhost:27017", "MongoDB URI")
	nickname := flag.String("nickname", "", "Provider nickname to update")
	host := flag.String("host", "", "New host_address value")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(*mongoAddr))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	coll := client.Database("gads").Collection("providers")

	if *nickname != "" && *host != "" {
		res, err := coll.UpdateOne(ctx, bson.M{"nickname": *nickname}, bson.M{"$set": bson.M{"host_address": *host}})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("updated matched=%d modified=%d nickname=%s host=%s\n", res.MatchedCount, res.ModifiedCount, *nickname, *host)
	}

	cursor, err := coll.Find(ctx, bson.M{})
	if err != nil {
		log.Fatal(err)
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var p provider
		if err := cursor.Decode(&p); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("provider nickname=%s host=%s port=%d ios=%v\n", p.Nickname, p.HostAddress, p.Port, p.ProvideIOS)
	}
	if err := cursor.Err(); err != nil {
		log.Fatal(err)
	}
}
