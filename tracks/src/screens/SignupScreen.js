import React from "react";
import { View, StyleSheet, Text, Button } from "react-native";

const SignupScreen = ({ navigation }) => {
	return (
		<>
			<Text>SignupScreen</Text>
			<Button
				title='Go to Sigin'
				onPress={() => navigation.navigate("Signin")}
			/>
			<Button
				title='Go to main flow'
				onPress={() => navigation.navigate("mainFlow")}
			/>
		</>
	);
};

const styles = StyleSheet.create({});

export default SignupScreen;
