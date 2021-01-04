import React, { useReducer } from 'react';
import axios from 'axios';
import AuthContext from './authContext';
import authReducer from './authReducer';
import {
    REGISTER_SUCCESS,
    REGISTER_FAILD,
    USER_LOADED,
    AUTH_ERROR,
    LOGIN_SUCCESS,
    LOGIN_FAIL,
    LOGOUT,
    CLEAR_ERRORS
} from '../types'

const AuthState = props => {
    const initialState = {
        token: localStorage.getItem('token'), // access browser local storage
        isAuthenticated: null,
        loading: true,
        user: null,
        error: null
    };

    const [state, dispatch] = useReducer(authReducer, initialState);

    // Load User
    const loadUser = () => console.log('loadUser');

    // Register User
    const register = async formData => {
        const config = {
            headers: {
                'Content-Type': 'application/json'
            }
        }

        try{
            const res = await axios.post('api/users', formData, config); // this is enough as we have a proxy value set
            dispatch({
                type: REGISTER_SUCCESS,
                payload: res.data
            })
        } catch (err){
            dispatch({
                type: REGISTER_FAILD,
                payload: err.response.data.msg
            })
        }
    }

    // Login User
    const login = () => console.log('login');

    // Logout
    const logout = () => console.log('logout');

    // Clear Errors
    const clearErrors = () => dispatch({ type: CLEAR_ERRORS});

    return (
        <AuthContext.Provider
            value = {{
                token: state.token,
                isAuthenticated: state.isAuthenticated,
                loading: state.loading,
                user: state.user,
                error: state.error,
                loadUser,
                register,
                login,
                logout,
                clearErrors,
            }}
        >
            
            { props.children }
        </AuthContext.Provider>
    )
}

export default AuthState;